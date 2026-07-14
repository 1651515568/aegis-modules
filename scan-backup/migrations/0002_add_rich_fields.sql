-- 补充 findings 表的富化字段，与内存态 Hit 结构完全对齐。
-- 使用 ALTER TABLE ADD COLUMN（SQLite 支持）；DEFAULT '' / '[]' 保证旧行兼容。
ALTER TABLE m_scan_backup_findings ADD COLUMN detail             TEXT NOT NULL DEFAULT '';
ALTER TABLE m_scan_backup_findings ADD COLUMN sample             TEXT NOT NULL DEFAULT '';
ALTER TABLE m_scan_backup_findings ADD COLUMN remediation        TEXT NOT NULL DEFAULT '';
ALTER TABLE m_scan_backup_findings ADD COLUMN refs               TEXT NOT NULL DEFAULT '[]';
ALTER TABLE m_scan_backup_findings ADD COLUMN chain              TEXT NOT NULL DEFAULT '[]';
ALTER TABLE m_scan_backup_findings ADD COLUMN evidence_request   TEXT NOT NULL DEFAULT '';
ALTER TABLE m_scan_backup_findings ADD COLUMN evidence_response  TEXT NOT NULL DEFAULT '';
ALTER TABLE m_scan_backup_findings ADD COLUMN evidence_note      TEXT NOT NULL DEFAULT '';
