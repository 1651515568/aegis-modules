-- m_scan_port_findings：按系统 task_id 归档的开放端口命中记录。
-- 与内存态 /ports(仅最近一次扫描的实时视图)互补：本表持久化、按 task_id 可查、
-- 跨进程重启不丢。一次扫描结束时把开放端口按其 task_id 落库，系统据 task_id 即可取回。
-- 表名须自带 m_<id>_ 前缀(框架不改写 SQL)；scan-port → m_scan_port_。
CREATE TABLE IF NOT EXISTS m_scan_port_findings (
  task_id    TEXT NOT NULL,
  hit_id     TEXT NOT NULL,
  host       TEXT NOT NULL DEFAULT '',
  port       INTEGER NOT NULL DEFAULT 0,
  proto      TEXT NOT NULL DEFAULT '',
  service    TEXT NOT NULL DEFAULT '',
  banner     TEXT NOT NULL DEFAULT '',
  found_at   TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (task_id, hit_id)
);

CREATE INDEX IF NOT EXISTS idx_m_scan_port_findings_task ON m_scan_port_findings (task_id);
