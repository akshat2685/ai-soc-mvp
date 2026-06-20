CREATE TABLE IF NOT EXISTS analyst_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    override_type TEXT NOT NULL,
    override_reason TEXT,
    original_confidence REAL,
    corrected_confidence REAL,
    time_to_override INTEGER,
    processed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
