ALTER TABLE deployments
    ADD COLUMN registry_credential_id uuid,
    ADD COLUMN registry_credential_server text NOT NULL DEFAULT '',
    ADD COLUMN registry_credential_username text NOT NULL DEFAULT '',
    ADD COLUMN encrypted_registry_credential text NOT NULL DEFAULT '',
    ADD CONSTRAINT deployments_registry_credential_snapshot_check CHECK (
        (registry_credential_id IS NULL AND registry_credential_server='' AND registry_credential_username='' AND encrypted_registry_credential='')
        OR
        (registry_credential_id IS NOT NULL AND registry_credential_server<>'' AND registry_credential_username<>'' AND encrypted_registry_credential<>'')
    );

-- Existing history did not retain credential identity. Preserve the current
-- binding as a best-effort upgrade path; all new deployments snapshot it while
-- the service row is locked.
UPDATE deployments deployment
SET registry_credential_id=credential.id,
    registry_credential_server=credential.server,
    registry_credential_username=credential.username,
    encrypted_registry_credential=credential.encrypted_secret
FROM application_sources source
JOIN source_credentials credential ON credential.id=source.registry_credential_id AND credential.kind='registry'
WHERE source.compose_service_id=deployment.compose_service_id
  AND credential.server<>''
  AND credential.username<>''
  AND credential.encrypted_secret<>'';
