ALTER TABLE template_repositories
    ADD COLUMN trusted_public_key text NOT NULL DEFAULT '',
    ADD COLUMN require_signature boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT template_repositories_signature_key_check
        CHECK (NOT require_signature OR trusted_public_key <> '');
