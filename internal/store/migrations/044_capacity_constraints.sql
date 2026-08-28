ALTER TABLE environments
    ADD COLUMN minimum_nano_cpus bigint NOT NULL DEFAULT 0 CHECK (minimum_nano_cpus BETWEEN 0 AND 1000000000000),
    ADD COLUMN minimum_memory_bytes bigint NOT NULL DEFAULT 0 CHECK (minimum_memory_bytes BETWEEN 0 AND 1125899906842624);
