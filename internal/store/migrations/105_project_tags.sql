CREATE TABLE project_tags (
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, tag_id)
);

CREATE INDEX project_tags_tag_idx ON project_tags(tag_id);
