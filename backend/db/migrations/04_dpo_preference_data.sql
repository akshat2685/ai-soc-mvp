CREATE TABLE IF NOT EXISTS dpo_preference_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT NOT NULL,
    prompt TEXT NOT NULL,
    chosen_response TEXT NOT NULL,
    rejected_response TEXT NOT NULL,
    chosen_score REAL NOT NULL,
    rejected_score REAL NOT NULL,
    adversarial_difficulty TEXT DEFAULT 'LOW',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
