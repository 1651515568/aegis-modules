-- m_ssl_audit_findings: 按 task_id 归档的 SSL/TLS 问题发现记录。
-- 表名带 m_ssl_audit_ 前缀（框架不改写 SQL，-→_ 替换）。
CREATE TABLE IF NOT EXISTS m_ssl_audit_findings (
    id        TEXT NOT NULL,
    task_id   TEXT NOT NULL,
    host      TEXT NOT NULL DEFAULT '',
    port      INTEGER NOT NULL DEFAULT 443,
    severity  TEXT NOT NULL DEFAULT 'info',
    category  TEXT NOT NULL DEFAULT '',
    label     TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT '',
    evidence  TEXT NOT NULL DEFAULT '',
    found_at  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, id)
);
CREATE INDEX IF NOT EXISTS idx_m_ssl_audit_findings_task ON m_ssl_audit_findings(task_id);

-- m_ssl_audit_certs: 每次扫描对应的证书详情，按 task_id + host 归档。
CREATE TABLE IF NOT EXISTS m_ssl_audit_certs (
    id          TEXT NOT NULL,
    task_id     TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 443,
    subject     TEXT NOT NULL DEFAULT '',
    issuer      TEXT NOT NULL DEFAULT '',
    not_before  TEXT NOT NULL DEFAULT '',
    not_after   TEXT NOT NULL DEFAULT '',
    days_left   INTEGER NOT NULL DEFAULT 0,
    key_type    TEXT NOT NULL DEFAULT '',
    key_bits    INTEGER NOT NULL DEFAULT 0,
    sig_algo    TEXT NOT NULL DEFAULT '',
    sans        TEXT NOT NULL DEFAULT '',
    tls_version TEXT NOT NULL DEFAULT '',
    cipher      TEXT NOT NULL DEFAULT '',
    hsts        TEXT NOT NULL DEFAULT '',
    self_signed INTEGER NOT NULL DEFAULT 0,
    scan_err    TEXT NOT NULL DEFAULT '',
    found_at    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, id)
);
CREATE INDEX IF NOT EXISTS idx_m_ssl_audit_certs_task ON m_ssl_audit_certs(task_id);
