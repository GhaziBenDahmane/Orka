CREATE INDEX cluster_commands_history_idx
    ON cluster_commands(cluster_id,kind,created_at DESC,id DESC);
