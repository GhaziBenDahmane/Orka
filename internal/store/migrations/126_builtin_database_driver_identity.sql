ALTER TABLE database_instances
    DROP CONSTRAINT database_driver_identity_consistent;

UPDATE database_instances
SET driver_source='unbound',driver_artifact_digest=''
WHERE driver_source='built-in'
  AND engine NOT IN ('postgres','timescaledb','mysql','mariadb','mongo','valkey','redis','libsql','clickhouse','qdrant','meilisearch');

UPDATE database_instances
SET driver_artifact_digest=CASE engine
    WHEN 'postgres' THEN 'sha256:45d02068e52234173729994da8d091dba83fa904dd78b9661bdf4418008009f1'
    WHEN 'timescaledb' THEN 'sha256:c3bfe3fbfd313132c68b699fbccd356c926c0da726dd962f10ac94ef1ae32551'
    WHEN 'mysql' THEN 'sha256:38104a44da90e33a30c959238e81a21d8d9ead0fcd86b639c96a093a0f1d2c26'
    WHEN 'mariadb' THEN 'sha256:60a30744331136bc2a4eee722f5c4df2aecb1014cfc4ee8f4cf1af32011193e1'
    WHEN 'mongo' THEN 'sha256:7196718d984837cea992fcea183622563e3020373016ccc6780a4a348e69c293'
    WHEN 'valkey' THEN 'sha256:7b226015d722b63ad3dc1539ee62e5ae796cbbf833d8da8eadc069411f297164'
    WHEN 'redis' THEN 'sha256:75779535af8a4f5add3364e66529e743e680c0ab8e214d3014b2f9d55b4bf027'
    WHEN 'libsql' THEN 'sha256:6f129954cc9d4551d1bc4f68a7bcc2aa8db9798e01019c614895401bf4c6c610'
    WHEN 'clickhouse' THEN 'sha256:891977a7f64f1c4479fa1682183fd5054cb8f1fea3f7490eecae4ffa9ca63204'
    WHEN 'qdrant' THEN 'sha256:c6003cf7c8f97928db5025bb3a6084c9c6f2215a5309078c67192babbca04fb9'
    WHEN 'meilisearch' THEN 'sha256:1ba009e1733d902c3d27044fab76e79e818e3413e2a534b56a39a6f4494ed36e'
END
WHERE driver_source='built-in';

ALTER TABLE database_instances
    ADD CONSTRAINT database_driver_identity_consistent CHECK (
        (driver_source IN ('built-in','external') AND driver_artifact_digest ~ '^sha256:[a-f0-9]{64}$') OR
        (driver_source='unbound' AND driver_artifact_digest='')
    );
