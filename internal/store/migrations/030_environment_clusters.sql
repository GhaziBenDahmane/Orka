ALTER TABLE environments ADD COLUMN cluster_id uuid REFERENCES clusters(id) ON DELETE RESTRICT;
CREATE INDEX environments_cluster_idx ON environments(cluster_id) WHERE cluster_id IS NOT NULL;
