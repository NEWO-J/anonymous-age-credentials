# anonymous-age-credentials

Age assurance that does not identify anyone. A user proves they are over 18 once,
gets a credential the issuer cannot read, and spends it exactly once at a
relying party.

Two properties hold it together:

- **Unlinkable.** The issuer blind signs a token it never sees. What it signs is
  `m * r^e mod n` for a random `r`, which is uniform and independent of `m`, so
  there is nothing in the issuer's records to join against the verifier's.
- **Single use.** The verifier derives a nullifier from the credential and spends
  it against a Postgres primary key. Two concurrent claims of the same nullifier
  cannot both come back.

## Directory structure

```
aac/
├── issuer/
│   ├── issuer.py                # /challenge /sign /key - blind signs, never sees the token
│   ├── Dockerfile
│   └── requirements.txt
│
├── verifier/
│   ├── verifier.py              # /redeem - PSS verify then spend the nullifier
│   ├── Dockerfile
│   └── requirements.txt
│
├── nullifier/
│   ├── src/main.rs              # Rust: /claim - sharded bloom cache + batched postgres writes
│   ├── Cargo.toml
│   └── Dockerfile
│
├── bench/
│   └── wrk_claim.lua            # wrk script, fresh nullifier per request
│
├── tests/
│   └── test_aac.py              # blind signature maths + double spend + concurrent claims
│
├── client.py                    # holder, dev IdP and the end to end demo
├── schema.sql                   # signing_keys, grants, nullifiers (hash partitioned x16)
└── docker-compose.yml           # db, cache, nullifier, issuer, verifier
```

## Running it

```
cp .env.example .env            # then change every secret in it
docker compose up --build -d
python client.py
```

```
subject     user-dec043b6cadb
credential  aac1.eyJraWQiOiJhZ2UxOC4yMDI2LTA5LjExYjcwMmY1OGNjMTZkMGQ...
nullifier   b1a06f2ab234a3b6bdd15fc1080193a0802df6674590eb0fbaacbab0441aa445
redeem #1   accepted
redeem #2   replayed

ok, one credential spent once and nothing ties it to the subject
```

## How the flow works

1. An identity provider signs a JWT saying a subject is over 18. This is the only
   place a real identity exists. `client.py` fakes one for local runs.
2. `POST /challenge` checks that JWT, hashes the subject with a pepper and writes
   a one shot grant. The unique index on `(subject, epoch)` is the anti farming
   control, one credential per person per month.
3. The client builds `"aac/credential/v1" || key_id || token_id`, PSS encodes it,
   multiplies by `r^e` and sends that. `POST /sign` raises it to `d` and returns
   it. The issuer sees a random number.
4. The client divides `r` back out and is left with a normal RSA PSS signature.
5. `POST /redeem` verifies it, derives
   `sha256("aac/nullifier/v1" || key_id || token_id)` and claims it. First claim
   wins, everything after is a replay.

`key_id` is inside the signed message, so a credential cannot be moved to another
month or another attribute. Everyone issued under the same key is
indistinguishable, which is why the epoch is a whole month rather than a day.

## The nullifier store

Two tiers, not three. Postgres decides, the in process cache only ever answers
"already spent":

```
in process   64 shards, bloom filter + hash set     no network
postgres     INSERT .. ON CONFLICT DO NOTHING       authoritative
```

Caching a uniqueness check is normally a bug. It is safe here because spentness
is monotonic, a nullifier never becomes unspent, so a cache hit can be trusted
and a cache miss just falls through to Postgres. Only Postgres calls anything
fresh.

Throughput comes from three things:

- the claim statement is **prepared once per connection**, passing SQL text to
  `query()` re-prepares every call and re-plans the partitioned insert
- each connection has a **worker** that takes whatever queued behind the first
  job, so batches grow under load without waiting on a timer
- `nullifiers` is **hash partitioned 16 ways**, and nullifiers are sha256 output
  so they spread evenly

## Numbers

Measured with wrk on the compose stack, Docker Desktop on Windows, every request
carrying a fresh nullifier so all of them reach Postgres:

| connections | throughput | p50 | p90 | p99 |
| --- | --- | --- | --- | --- | --- |
| 16 | 1,571 req/s | 9.37 ms | 16.30 ms | 23.91 ms |
| 48 | 3,880 req/s | 13.42 ms | 17.18 ms | 22.86 ms |

```
set -a; . ./.env; set +a
docker run --rm --network aac_default -v "$PWD:/repo" \
  -e NULLIFIER_TOKEN -e REPLAY_PERCENT=10 \
  williamyeh/wrk -t4 -c48 -d30s --latency -s /repo/bench/wrk_claim.lua \
  http://nullifier:8081
```

The p99 tail is Postgres commit latency on a laptop VM disk, it is not the
service. `GET /stats` on the nullifier shows how many claims the cache absorbed
without touching the database.

## Tests

```
pip install -r tests/requirements.txt
pytest tests -q
```

The blind signature tests run standalone. The rest need the stack up and cover
double redemption, one credential per subject, a tampered credential, 32
concurrent redemptions of one credential landing on exactly one accept, and the
same nullifier sent twice in one request.

## What this does not do

- Timing correlation is not defended. Redeem seconds after issuance from the same
  address and the two are linked whatever the crypto does.
- The RSA private key operation uses Python `pow()`, which is not constant time.
  Blinding means the attacker does not control the input, but a real issuer puts
  this in an HSM.
- There is no per credential revocation and there cannot be, the issuer does not
  know which credentials exist. Rotating the monthly key is the only lever.
- The issuer does learn that a subject got a credential this month. That is
  unavoidable for any per person limit.
