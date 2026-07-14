-- Add favicon_hash column for Shodan/Fofa-compatible hash storage.
ALTER TABLE m_scan_probe_results ADD COLUMN favicon_hash INTEGER NOT NULL DEFAULT 0;
