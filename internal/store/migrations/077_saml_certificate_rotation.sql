ALTER TABLE saml_providers
    ADD COLUMN pending_certificate_pem text,
    ADD COLUMN pending_encrypted_private_key text,
    ADD COLUMN pending_certificate_not_after timestamptz,
    ADD COLUMN pending_certificate_created_at timestamptz,
    ADD CONSTRAINT saml_providers_pending_certificate_check CHECK (
        (pending_certificate_pem IS NULL AND pending_encrypted_private_key IS NULL AND pending_certificate_not_after IS NULL AND pending_certificate_created_at IS NULL)
        OR
        (pending_certificate_pem IS NOT NULL AND pending_encrypted_private_key IS NOT NULL AND pending_certificate_not_after IS NOT NULL AND pending_certificate_created_at IS NOT NULL)
    );
