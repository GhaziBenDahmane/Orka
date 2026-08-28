CREATE TABLE controller_leases (
    name text PRIMARY KEY,
    holder text NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
