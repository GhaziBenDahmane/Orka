ALTER TABLE clusters ADD COLUMN capacity jsonb NOT NULL DEFAULT '{}'::jsonb;
