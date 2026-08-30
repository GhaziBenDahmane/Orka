CREATE INDEX templates_catalog_page_idx ON templates (name, version DESC, id);
CREATE INDEX templates_key_versions_idx ON templates (template_key, version DESC, id);
