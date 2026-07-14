CREATE TABLE IF NOT EXISTS m_js_extract_findings (
  id        TEXT NOT NULL PRIMARY KEY,
  task_id   TEXT NOT NULL,
  js_url    TEXT NOT NULL DEFAULT '',
  page_url  TEXT NOT NULL DEFAULT '',
  category  TEXT NOT NULL DEFAULT '',
  severity  TEXT NOT NULL DEFAULT 'info',
  label     TEXT NOT NULL DEFAULT '',
  value     TEXT NOT NULL DEFAULT '',
  ctx       TEXT NOT NULL DEFAULT '',
  found_at  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_m_js_extract_findings_task ON m_js_extract_findings (task_id);
CREATE INDEX IF NOT EXISTS idx_m_js_extract_findings_cat  ON m_js_extract_findings (task_id, category);
