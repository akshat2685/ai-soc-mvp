CREATE TABLE IF NOT EXISTS federated_syncs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch INTEGER NOT NULL,
    tenant_count INTEGER NOT NULL,
    privacy_epsilon REAL NOT NULL,
    laplace_noise_scale REAL NOT NULL,
    gradient_norm REAL NOT NULL,
    status TEXT DEFAULT 'COMPLETED',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
