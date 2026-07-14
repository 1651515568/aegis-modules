CREATE TABLE IF NOT EXISTS m_webshell_shells (
    id          TEXT NOT NULL PRIMARY KEY,
    url         TEXT NOT NULL,
    shell_type  TEXT NOT NULL DEFAULT 'php',
    password    TEXT NOT NULL DEFAULT 'aegis',
    note        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'unknown',
    os_info     TEXT NOT NULL DEFAULT '',
    server_info TEXT NOT NULL DEFAULT '',
    php_version TEXT NOT NULL DEFAULT '',
    cwd         TEXT NOT NULL DEFAULT '',
    run_user    TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    server_ip   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT
);

CREATE INDEX IF NOT EXISTS idx_m_webshell_shells_status ON m_webshell_shells (status);
