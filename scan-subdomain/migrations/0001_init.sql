-- m_scan_subdomain_results: 按系统 task_id 归档的子域名枚举结果。
-- 表名须自带 m_<id>_ 前缀；scan-subdomain → m_scan_subdomain_。
CREATE TABLE IF NOT EXISTS m_scan_subdomain_results (
  task_id   TEXT NOT NULL,
  subdomain TEXT NOT NULL,
  ip        TEXT NOT NULL DEFAULT '',
  cdn       TEXT NOT NULL DEFAULT '—',
  status    INTEGER NOT NULL DEFAULT 0,
  title     TEXT NOT NULL DEFAULT '',
  source    TEXT NOT NULL DEFAULT '',
  found_at  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (task_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_m_scan_subdomain_results_task ON m_scan_subdomain_results (task_id);
