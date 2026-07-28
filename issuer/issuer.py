from fastapi import FastAPI, Body, HTTPException, Depends, Request, Header
from fastapi.responses import JSONResponse
from typing import Annotated

import psycopg
from psycopg_pool import ConnectionPool

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import base64
import hashlib
import hmac
import jwt
from jwt import DecodeError, ExpiredSignatureError

import os
import redis

import uuid
import time
import datetime

app = FastAPI()

idp_secret = os.environ.get("IDP_SECRET")
pepper = os.environ.get("SUBJECT_PEPPER", "").encode()

pool = ConnectionPool(os.environ.get("DATABASE_URL"), min_size=2, max_size=10)
red = redis.Redis(host="cache", port=6379, db=0)

limit = 30
grant_ttl = 300

# the issuer signs a token it never sees, so the only per-person control it has
# is one grant per subject per epoch
def epoch():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m")


def rate_limiter(request: Request,
                 x_real_ip: Annotated[str | None, Header()] = None):

    ts = time.time()
    ip = x_real_ip or request.client.host
    key = f"rate_limit:issue:{ip}"

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


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def load_key():
    ep = epoch()

    with pool.connection() as conn:
        row = conn.execute("SELECT key_id, pem FROM signing_keys WHERE epoch = %s", (ep,)).fetchone()
        if row:
            key = serialization.load_pem_private_key(row[1].encode(), password=None)
            return row[0], key

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_id = f"age18.{ep}.{hashlib.sha256(pub).hexdigest()[:16]}"
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        conn.execute(
            "INSERT INTO signing_keys (key_id, epoch, pem) VALUES (%s, %s, %s) ON CONFLICT (epoch) DO NOTHING",
            (key_id, ep, pem),
        )
        conn.commit()

        # another replica may have won the insert
        row = conn.execute("SELECT key_id, pem FROM signing_keys WHERE epoch = %s", (ep,)).fetchone()
        return row[0], serialization.load_pem_private_key(row[1].encode(), password=None)


@app.get("/key")
def get_key():
    key_id, key = load_key()
    numbers = key.public_key().public_numbers()

    return JSONResponse(content={
        "key_id": key_id,
        "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": numbers.e,
    })


@app.post("/challenge")
def challenge(
    payload: dict = Body(...),
    ok: Annotated[bool, Depends(rate_limiter)] = None,
):

    token = payload.get("attestation")
    if not token:
        raise HTTPException(status_code=400, detail="Attestation is required")

    try:
        claims = jwt.decode(token, idp_secret, algorithms=["HS256"])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Attestation has expired")
    except DecodeError:
        raise HTTPException(status_code=401, detail="Attestation is not valid")

    if not claims.get("over18"):
        raise HTTPException(status_code=401, detail="Attestation does not assert over18")

    # the raw subject is never stored, only this
    subject = hmac.new(pepper, claims["sub"].encode(), hashlib.sha256).digest()

    key_id, key = load_key()
    ep = epoch()
    challenge_id = str(uuid.uuid4())
    expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=grant_ttl)

    with pool.connection() as conn:
        row = conn.execute(
            """INSERT INTO grants (challenge_id, subject, key_id, epoch, expires_at)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (subject, epoch) DO UPDATE SET challenge_id = EXCLUDED.challenge_id,
                                                          expires_at = EXCLUDED.expires_at
               WHERE grants.used = false AND grants.expires_at <= now()
               RETURNING challenge_id""",
            (challenge_id, subject, key_id, ep, expires),
        ).fetchone()
        conn.commit()

        if not row:
            existing = conn.execute(
                "SELECT challenge_id, used FROM grants WHERE subject = %s AND epoch = %s",
                (subject, ep),
            ).fetchone()

            if existing and existing[1]:
                raise HTTPException(status_code=409, detail=f"A credential was already issued for {ep}")
            if not existing:
                raise HTTPException(status_code=409, detail="Could not create a grant, try again")

            challenge_id = str(existing[0])

    numbers = key.public_key().public_numbers()

    return JSONResponse(content={
        "challenge_id": challenge_id,
        "key_id": key_id,
        "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": numbers.e,
    })


@app.post("/sign")
def sign(
    payload: dict = Body(...),
    ok: Annotated[bool, Depends(rate_limiter)] = None,
):

    challenge_id = payload.get("challenge_id")
    blinded = payload.get("blinded")

    if not challenge_id or not blinded:
        raise HTTPException(status_code=400, detail="challenge_id and blinded are required")

    try:
        uuid.UUID(challenge_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="challenge_id must be a uuid")

    # single use, decided by the database and not by us
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE grants SET used = true WHERE challenge_id = %s AND used = false AND expires_at > now() RETURNING key_id",
            (challenge_id,),
        ).fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=409, detail="Challenge is unknown, expired or already used")

    key_id, key = load_key()
    if row[0] != key_id:
        raise HTTPException(status_code=409, detail="Challenge was issued under a retired key")

    nums = key.private_numbers()
    n = nums.public_numbers.n
    m = int.from_bytes(unb64(blinded), "big")

    if m >= n:
        raise HTTPException(status_code=400, detail="Blinded message is out of range")

    # raw RSA over the blinded value, via CRT. this is the whole signing step
    s1 = pow(m % nums.p, nums.dmp1, nums.p)
    s2 = pow(m % nums.q, nums.dmq1, nums.q)
    h = (nums.iqmp * (s1 - s2)) % nums.p
    s = (s2 + h * nums.q) % n

    if pow(s, nums.public_numbers.e, n) != m:
        raise HTTPException(status_code=500, detail="Signing self check failed")

    size = (n.bit_length() + 7) // 8

    return JSONResponse(content={"key_id": key_id, "sig": b64(s.to_bytes(size, "big"))})


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
