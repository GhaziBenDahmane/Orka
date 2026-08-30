ALTER TABLE clusters ADD COLUMN capabilities jsonb NOT NULL DEFAULT '{}'::jsonb;
