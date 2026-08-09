import base64
import hashlib
import json
import os
import secrets
import sys
import time

import jwt
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

issuer_url = os.environ.get("ISSUER_URL", "http://localhost:8080")
verifier_url = os.environ.get("VERIFIER_URL", "http://localhost:8083")
idp_secret = os.environ.get("IDP_SECRET")

hash_len = 48
salt_len = 48


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def attest(subject):
    return jwt.encode(
        {"sub": subject, "over18": True, "exp": int(time.time()) + 300},
        idp_secret,
        algorithm="HS256",
    )


def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha384(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def pss_encode(msg, em_bits):
    em_len = (em_bits + 7) // 8
    m_hash = hashlib.sha384(msg).digest()
    salt = secrets.token_bytes(salt_len)

    h = hashlib.sha384(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - salt_len - hash_len - 2) + b"\x01" + salt
    masked = bytearray(x ^ y for x, y in zip(db, mgf1(h, em_len - hash_len - 1)))

    unused = 8 * em_len - em_bits
    if unused:
        masked[0] &= 0xFF >> unused

    return bytes(masked) + h + b"\xbc"


def obtain(subject):
    r = requests.post(f"{issuer_url}/challenge", json={"attestation": attest(subject)}, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f"challenge failed: {r.status_code} {r.text}")

    challenge = r.json()
    key_id = challenge["key_id"]
    n = int.from_bytes(unb64(challenge["n"]), "big")
    e = challenge["e"]
    size = (n.bit_length() + 7) // 8

    # the issuer never sees any of this
    token_id = secrets.token_bytes(32)
    randomizer = secrets.token_bytes(32)
    msg = b"aac/credential/v1" + b"\x00" + key_id.encode() + b"\x00" + token_id

    m = int.from_bytes(pss_encode(randomizer + msg, n.bit_length() - 1), "big")

    while True:
        r_blind = secrets.randbelow(n - 1) + 1
        try:
            inverse = pow(r_blind, -1, n)
            break
        except ValueError:
            continue

    # m * r^e is uniform for uniform r, so the issuer learns nothing about m
    blinded = (m * pow(r_blind, e, n)) % n

    r = requests.post(
        f"{issuer_url}/sign",
        json={"challenge_id": challenge["challenge_id"], "blinded": b64(blinded.to_bytes(size, "big"))},
        timeout=30,
    )
    if r.status_code != 200:
        raise SystemExit(f"sign failed: {r.status_code} {r.text}")

    blind_sig = int.from_bytes(unb64(r.json()["sig"]), "big")
    sig = ((blind_sig * inverse) % n).to_bytes(size, "big")

    credential = {"kid": key_id, "tid": b64(token_id), "r": b64(randomizer), "sig": b64(sig)}
    nullifier = hashlib.sha256(b"aac/nullifier/v1" + b"\x00" + key_id.encode() + b"\x00" + token_id).hexdigest()

    return "aac1." + b64(json.dumps(credential, separators=(",", ":")).encode()), nullifier


def redeem(credential):
    r = requests.post(f"{verifier_url}/redeem", json={"credential": credential}, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f"redeem failed: {r.status_code} {r.text}")
    return r.json()["status"]


if __name__ == "__main__":
    if not idp_secret:
        raise SystemExit("IDP_SECRET is not set, source your .env first")

    subject = sys.argv[1] if len(sys.argv) > 1 else f"user-{secrets.token_hex(6)}"

    credential, nullifier = obtain(subject)
    print(f"subject     {subject}")
    print(f"credential  {credential[:56]}...")
    print(f"nullifier   {nullifier}")

    first = redeem(credential)
    second = redeem(credential)
    print(f"redeem #1   {first}")
    print(f"redeem #2   {second}")

    if first != "accepted" or second != "replayed":
        raise SystemExit("double redemption was not prevented")

    print("\nok, one credential spent once and nothing ties it to the subject")
