-- m_scan_probe_results: 按系统 task_id 归档的指纹探测结果。
-- 表名须自带 m_<id>_ 前缀；scan-probe → m_scan_probe_。
CREATE TABLE IF NOT EXISTS m_scan_probe_results (
  task_id     TEXT NOT NULL,
  host        TEXT NOT NULL,
  port        INTEGER NOT NULL DEFAULT 80,
  protocol    TEXT NOT NULL DEFAULT 'http',
  cms         TEXT NOT NULL DEFAULT '—',
  framework   TEXT NOT NULL DEFAULT '—',
  waf         TEXT NOT NULL DEFAULT '无',
  server      TEXT NOT NULL DEFAULT '',
  title       TEXT NOT NULL DEFAULT '',
  status_code INTEGER NOT NULL DEFAULT 0,
  os          TEXT NOT NULL DEFAULT '—',
  found_at    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (task_id, host, port)
);

CREATE INDEX IF NOT EXISTS idx_m_scan_probe_results_task ON m_scan_probe_results (task_id);
