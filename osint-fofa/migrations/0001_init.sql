-- m_osint_fofa_findings：按系统 task_id 归档的空间测绘查询资产记录。
-- 与任务进度表互补：本表持久化，按 task_id 可查，跨进程重启不丢。
-- 一次查询结束后把去重资产按其 task_id 落库，系统据 task_id 即可取回。
-- 表名须自带 m_<id>_ 前缀（框架不改写 SQL）；osint-fofa → m_osint_fofa_。
CREATE TABLE IF NOT EXISTS m_osint_fofa_findings (
    task_id     TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 0,
    domain      TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL DEFAULT '',
    banner      TEXT NOT NULL DEFAULT '',
    country     TEXT NOT NULL DEFAULT '',
    city        TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (task_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_m_osint_fofa_findings_task ON m_osint_fofa_findings(task_id);

-- m_osint_fofa_settings：存储各平台 API Key 配置。
CREATE TABLE IF NOT EXISTS m_osint_fofa_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
