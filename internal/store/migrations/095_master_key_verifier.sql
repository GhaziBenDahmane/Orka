CREATE TABLE master_key_verifier (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    ciphertext text NOT NULL CHECK (ciphertext <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
