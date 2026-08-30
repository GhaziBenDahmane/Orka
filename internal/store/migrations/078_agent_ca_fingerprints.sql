ALTER TABLE clusters
    ADD COLUMN certificate_ca_fingerprint text NOT NULL DEFAULT '',
    ADD COLUMN pending_certificate_ca_fingerprint text NOT NULL DEFAULT '',
    ADD CONSTRAINT clusters_certificate_ca_fingerprint_check CHECK (
        certificate_ca_fingerprint='' OR certificate_ca_fingerprint ~ '^sha256:[a-f0-9]{64}$'
    ),
    ADD CONSTRAINT clusters_pending_certificate_ca_fingerprint_check CHECK (
        pending_certificate_ca_fingerprint='' OR pending_certificate_ca_fingerprint ~ '^sha256:[a-f0-9]{64}$'
    );
