from fastapi import FastAPI, Body, HTTPException, Depends, Request, Header
from fastapi.responses import JSONResponse
from typing import Annotated

from psycopg_pool import ConnectionPool

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import base64
import hashlib
import json
import requests

import os
import redis

import uuid
import time

app = FastAPI()

pool = ConnectionPool(os.environ.get("DATABASE_URL"), min_size=2, max_size=10)
red = redis.Redis(host="cache", port=6379, db=0)

nullifier_url = os.environ.get("NULLIFIER_URL", "http://nullifier:8081")
nullifier_token = os.environ.get("NULLIFIER_TOKEN", "")

limit = 600
salt_len = 48

session = requests.Session()

keys = {}


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rate_limiter(request: Request,
                 x_real_ip: Annotated[str | None, Header()] = None):

    ts = time.time()
    ip = x_real_ip or request.client.host
    key = f"rate_limit:redeem:{ip}"

    r = red.pipeline()
    r.zremrangebyscore(key, 0, ts - 60)
    r.zcard(key)
    time_id = f"time-{uuid.uuid4().hex}"
    r.zadd(key, {time_id: ts})
    r.expire(key, 65)

    results = r.execute()
    current_count = results[1]

    if current_count >= limit:
        r.zrem(key, time_id)
        raise HTTPException(status_code=429, detail="Too many requests, try again later")
    else:
        return True


def public_key(key_id):
    if key_id in keys:
        return keys[key_id]

    with pool.connection() as conn:
        row = conn.execute("SELECT pem FROM signing_keys WHERE key_id = %s", (key_id,)).fetchone()

    if not row:
        return None

    key = serialization.load_pem_private_key(row[0].encode(), password=None).public_key()
    keys[key_id] = key
    return key


@app.post("/redeem")
def redeem(
    payload: dict = Body(...),
    ok: Annotated[bool, Depends(rate_limiter)] = None,
):

    token = payload.get("credential")
    if not token:
        raise HTTPException(status_code=400, detail="credential is required")

    prefix, _, body = token.partition(".")
    if prefix != "aac1" or not body:
        raise HTTPException(status_code=400, detail="Not an aac1 credential")

    try:
        cred = json.loads(unb64(body))
        key_id = cred["kid"]
        token_id = unb64(cred["tid"])
        randomizer = unb64(cred["r"])
        sig = unb64(cred["sig"])
    except Exception:
        raise HTTPException(status_code=400, detail="Credential is malformed")

    if len(token_id) != 32 or len(randomizer) != 32:
        raise HTTPException(status_code=400, detail="Credential is malformed")

    key = public_key(key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Unknown key id")

    msg = b"aac/credential/v1" + b"\x00" + key_id.encode() + b"\x00" + token_id

    # ordinary PSS verify, the blinding is long gone by this point
    try:
        key.verify(
            sig,
            randomizer + msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=salt_len),
            hashes.SHA384(),
        )
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Credential signature is invalid")

    nullifier = hashlib.sha256(b"aac/nullifier/v1" + b"\x00" + key_id.encode() + b"\x00" + token_id).hexdigest()

    # verify first, spend second, so junk never reaches the store
    try:
        r = session.post(
            f"{nullifier_url}/claim",
            json={"nullifiers": [nullifier]},
            headers={"authorization": f"Bearer {nullifier_token}"},
            timeout=2,
        )
        r.raise_for_status()
        result = r.json()["results"][0]
    except Exception:
        # no authoritative answer means we cannot rule out a double spend
        raise HTTPException(status_code=503, detail="Nullifier store is unavailable")

    return JSONResponse(content={"status": result["status"], "key_id": key_id})


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
