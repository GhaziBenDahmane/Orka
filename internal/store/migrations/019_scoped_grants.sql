CREATE TABLE project_grants (
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('admin','developer','viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE environment_grants (
    environment_id uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('admin','developer','viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (environment_id, user_id)
);

CREATE INDEX project_grants_user_idx ON project_grants(user_id);
CREATE INDEX environment_grants_user_idx ON environment_grants(user_id);
