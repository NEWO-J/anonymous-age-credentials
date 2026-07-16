CREATE TABLE IF NOT EXISTS signing_keys (
    key_id  text PRIMARY KEY,
    epoch   text NOT NULL UNIQUE,
    pem     text NOT NULL
);

-- one grant per subject per epoch. this unique index is the anti farming
-- control, it is not something the application can race past
CREATE TABLE IF NOT EXISTS grants (
    challenge_id uuid PRIMARY KEY,
    subject      bytea NOT NULL,
    key_id       text NOT NULL,
    epoch        text NOT NULL,
    used         boolean NOT NULL DEFAULT false,
    expires_at   timestamptz NOT NULL,
    UNIQUE (subject, epoch)
);

-- the spent set. the primary key is what makes double redemption impossible,
-- two concurrent inserts of the same nullifier cannot both come back
CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier  bytea NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (nullifier)
) PARTITION BY HASH (nullifier);

DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS nullifiers_p%s PARTITION OF nullifiers
                        FOR VALUES WITH (MODULUS 16, REMAINDER %s)', i, i);
    END LOOP;
END
$$;
