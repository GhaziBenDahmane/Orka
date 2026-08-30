ALTER TABLE users
    ADD COLUMN pending_encrypted_totp_secret text,
    ADD COLUMN encrypted_totp_secret text,
    ADD COLUMN totp_last_counter bigint,
    ADD CONSTRAINT users_totp_state_check CHECK (
        (encrypted_totp_secret IS NULL OR pending_encrypted_totp_secret IS NULL)
        AND (totp_last_counter IS NULL OR (encrypted_totp_secret IS NOT NULL AND totp_last_counter >= 0))
    );

CREATE TABLE user_mfa_recovery_codes (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_hash),
    CHECK (octet_length(code_hash) = 32)
);

CREATE INDEX user_mfa_recovery_codes_user_created_idx
    ON user_mfa_recovery_codes(user_id, created_at);
