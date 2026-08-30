ALTER TABLE routes
    ADD COLUMN internal_path text NOT NULL DEFAULT '/',
    ADD COLUMN strip_path boolean NOT NULL DEFAULT false,
    ADD COLUMN enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN redirect_regex text NOT NULL DEFAULT '',
    ADD COLUMN redirect_replacement text NOT NULL DEFAULT '',
    ADD COLUMN redirect_permanent boolean NOT NULL DEFAULT false,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
