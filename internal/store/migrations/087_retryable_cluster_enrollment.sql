ALTER TABLE cluster_enrollment_tokens
    ADD COLUMN enrollment_csr_sha256 bytea,
    ADD COLUMN issued_certificate text NOT NULL DEFAULT '',
    ADD COLUMN issued_ca_bundle text NOT NULL DEFAULT '',
    ADD COLUMN issued_signing_ca_certificate text NOT NULL DEFAULT '',
    ADD COLUMN issued_signing_ca_fingerprint text NOT NULL DEFAULT '';
