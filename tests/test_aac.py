import concurrent.futures
import hashlib
import json
import os
import secrets
import sys

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client import attest, b64, obtain, pss_encode, unb64  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

issuer_url = os.environ.get("ISSUER_URL", "http://localhost:8080")
verifier_url = os.environ.get("VERIFIER_URL", "http://localhost:8083")
nullifier_url = os.environ.get("NULLIFIER_URL", "http://localhost:8081")
nullifier_token = os.environ.get("NULLIFIER_TOKEN", "")


def stack_is_up():
    try:
        return requests.get(f"{issuer_url}/healthz", timeout=2).status_code == 200
    except Exception:
        return False


needs_stack = pytest.mark.skipif(not stack_is_up(), reason="start the stack with docker compose up")


# the blind signature protocol on its own, no services involved
def blind_sign_roundtrip(key, msg):
    n = key.public_key().public_numbers().n
    e = key.public_key().public_numbers().e
    size = (n.bit_length() + 7) // 8

    m = int.from_bytes(pss_encode(msg, n.bit_length() - 1), "big")

    r = secrets.randbelow(n - 1) + 1
    inverse = pow(r, -1, n)
    blinded = (m * pow(r, e, n)) % n

    nums = key.private_numbers()
    s1 = pow(blinded % nums.p, nums.dmp1, nums.p)
    s2 = pow(blinded % nums.q, nums.dmq1, nums.q)
    h = (nums.iqmp * (s1 - s2)) % nums.p
    blind_sig = (s2 + h * nums.q) % n

    return ((blind_sig * inverse) % n).to_bytes(size, "big"), blinded


def test_unblinded_signature_is_a_normal_pss_signature():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    msg = b"over 18"

    sig, _ = blind_sign_roundtrip(key, msg)

    key.public_key().verify(
        sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48), hashes.SHA384()
    )


def test_signature_does_not_verify_for_another_message():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig, _ = blind_sign_roundtrip(key, b"message one")

    with pytest.raises(InvalidSignature):
        key.public_key().verify(
            sig,
            b"message two",
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
            hashes.SHA384(),
        )


def test_what_the_issuer_sees_is_different_every_time():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    seen = {blind_sign_roundtrip(key, b"same message")[1] for _ in range(8)}
    assert len(seen) == 8


@needs_stack
def test_issue_then_redeem_then_replay():
    credential, _ = obtain(f"test-{secrets.token_hex(6)}")

    first = requests.post(f"{verifier_url}/redeem", json={"credential": credential}, timeout=30)
    second = requests.post(f"{verifier_url}/redeem", json={"credential": credential}, timeout=30)

    assert first.json()["status"] == "accepted"
    assert second.json()["status"] == "replayed"


@needs_stack
def test_a_subject_only_gets_one_credential_per_epoch():
    subject = f"test-{secrets.token_hex(6)}"
    obtain(subject)

    r = requests.post(f"{issuer_url}/challenge", json={"attestation": attest(subject)}, timeout=30)
    assert r.status_code == 409


@needs_stack
def test_a_tampered_credential_is_refused():
    credential, _ = obtain(f"test-{secrets.token_hex(6)}")
    body = json.loads(unb64(credential.split(".")[1]))
    body["tid"] = b64(secrets.token_bytes(32))
    tampered = "aac1." + b64(json.dumps(body, separators=(",", ":")).encode())

    r = requests.post(f"{verifier_url}/redeem", json={"credential": tampered}, timeout=30)
    assert r.status_code == 400


@needs_stack
def test_concurrent_redemptions_accept_exactly_one():
    credential, _ = obtain(f"test-{secrets.token_hex(6)}")

    def spend(_):
        return requests.post(f"{verifier_url}/redeem", json={"credential": credential}, timeout=30).json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(spend, range(32)))

    statuses = [r["status"] for r in results]
    assert statuses.count("accepted") == 1
    assert statuses.count("replayed") == 31


@needs_stack
def test_the_same_nullifier_twice_in_one_request_is_claimed_once():
    n = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    r = requests.post(
        f"{nullifier_url}/claim",
        json={"nullifiers": [n, n]},
        headers={"authorization": f"Bearer {nullifier_token}"},
        timeout=10,
    )

    statuses = [item["status"] for item in r.json()["results"]]
    assert statuses == ["accepted", "replayed"]
