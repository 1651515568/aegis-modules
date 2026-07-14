ALTER TABLE m_js_extract_findings ADD COLUMN entropy  REAL NOT NULL DEFAULT 0;
ALTER TABLE m_js_extract_findings ADD COLUMN confident INTEGER NOT NULL DEFAULT 0;
ALTER TABLE m_js_extract_findings ADD COLUMN is_map   INTEGER NOT NULL DEFAULT 0;
