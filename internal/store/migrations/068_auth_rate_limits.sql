CREATE TABLE auth_rate_limits (
    bucket text NOT NULL,
    key_hash bytea NOT NULL,
    window_started_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 1 CHECK (attempts > 0),
    PRIMARY KEY (bucket, key_hash)
);

CREATE INDEX auth_rate_limits_window_idx ON auth_rate_limits(window_started_at);
