ALTER TABLE projects ADD COLUMN deletion_requested_at timestamptz;
ALTER TABLE environments ADD COLUMN deletion_requested_at timestamptz;
ALTER TABLE clusters ADD COLUMN deletion_requested_at timestamptz;

CREATE INDEX projects_deleting_idx ON projects(deletion_requested_at) WHERE deletion_requested_at IS NOT NULL;
CREATE INDEX environments_deleting_idx ON environments(deletion_requested_at) WHERE deletion_requested_at IS NOT NULL;
CREATE INDEX clusters_deleting_idx ON clusters(deletion_requested_at) WHERE deletion_requested_at IS NOT NULL;
