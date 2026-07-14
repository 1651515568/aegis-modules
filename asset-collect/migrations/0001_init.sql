CREATE TABLE IF NOT EXISTS m_asset_collect_results (
  task_id  TEXT NOT NULL,
  type     TEXT NOT NULL DEFAULT '',
  value    TEXT NOT NULL DEFAULT '',
  org      TEXT NOT NULL DEFAULT '',
  source   TEXT NOT NULL DEFAULT '',
  meta     TEXT NOT NULL DEFAULT '',
  found_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (task_id, type, value)
);
