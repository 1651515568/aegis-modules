-- Add components column for storing full matched tech-stack as JSON array.
ALTER TABLE m_scan_probe_results ADD COLUMN components TEXT NOT NULL DEFAULT '[]';
