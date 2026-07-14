CREATE TABLE IF NOT EXISTS m_asset_collect_settings (
  key        TEXT NOT NULL PRIMARY KEY,
  value      TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
