-- m_scan_dir_findings：按系统 task_id 归档的目录/文件命中记录。
-- 与内存态 /hits(仅最近一次扫描的实时视图)互补：本表持久化、按 task_id 可查、
-- 跨进程重启不丢。一次扫描结束时把命中按其 task_id 落库，系统据 task_id 即可取回。
-- 表名须自带 m_<id>_ 前缀(框架不改写 SQL)；scan-dir → m_scan_dir_。
CREATE TABLE IF NOT EXISTS m_scan_dir_findings (
  task_id      TEXT NOT NULL,
  hit_id       TEXT NOT NULL,
  url          TEXT NOT NULL DEFAULT '',
  path         TEXT NOT NULL DEFAULT '',
  status       INTEGER NOT NULL DEFAULT 0,
  length       INTEGER NOT NULL DEFAULT 0,
  words        INTEGER NOT NULL DEFAULT 0,
  lines        INTEGER NOT NULL DEFAULT 0,
  redirect     TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT '',
  depth        INTEGER NOT NULL DEFAULT 0,
  severity     TEXT NOT NULL DEFAULT '',
  kind         TEXT NOT NULL DEFAULT '',
  found_at     TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (task_id, hit_id)
);

CREATE INDEX IF NOT EXISTS idx_m_scan_dir_findings_task ON m_scan_dir_findings (task_id);
