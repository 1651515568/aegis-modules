-- m_brute_force_results: 按任务归档的弱口令爆破结果。
-- 表名须自带 m_<id>_ 前缀；brute-force → m_brute_force_。
CREATE TABLE IF NOT EXISTS m_brute_force_results (
  task_id   TEXT NOT NULL,
  protocol  TEXT NOT NULL DEFAULT '',
  target    TEXT NOT NULL DEFAULT '',
  username  TEXT NOT NULL DEFAULT '',
  password  TEXT NOT NULL DEFAULT '',
  success   INTEGER NOT NULL DEFAULT 0,
  errmsg    TEXT NOT NULL DEFAULT '',
  found_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (task_id, protocol, target, username, password)
);

CREATE INDEX IF NOT EXISTS idx_m_brute_force_results_task ON m_brute_force_results (task_id);
CREATE INDEX IF NOT EXISTS idx_m_brute_force_results_success ON m_brute_force_results (task_id, success);

-- m_brute_force_settings: 模块持久化配置。
CREATE TABLE IF NOT EXISTS m_brute_force_settings (
  key        TEXT NOT NULL PRIMARY KEY,
  value      TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
