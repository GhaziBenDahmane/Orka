ALTER TABLE clusters
    ADD COLUMN pending_certificate_serial text NOT NULL DEFAULT '',
    ADD COLUMN pending_certificate_not_after timestamptz,
    ADD COLUMN pending_certificate_created_at timestamptz,
    ADD CONSTRAINT clusters_pending_certificate_check CHECK (
        (pending_certificate_serial='' AND pending_certificate_not_after IS NULL AND pending_certificate_created_at IS NULL)
        OR (pending_certificate_serial<>'' AND pending_certificate_not_after IS NOT NULL AND pending_certificate_created_at IS NOT NULL)
    );
