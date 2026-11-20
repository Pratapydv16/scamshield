CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    plan VARCHAR(32) NOT NULL DEFAULT 'free',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_users_email ON users(email);

CREATE TABLE scans (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES users(id) ON DELETE SET NULL,
    scan_type VARCHAR(16) NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level VARCHAR(16) NOT NULL,
    input_digest VARCHAR(64) NOT NULL,
    explanation TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_scans_user_id ON scans(user_id);
CREATE INDEX ix_scans_scanned_at ON scans(scanned_at);

CREATE TABLE scan_findings (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    code VARCHAR(64) NOT NULL,
    title VARCHAR(160) NOT NULL,
    detail TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL
);
CREATE INDEX ix_scan_findings_scan_id ON scan_findings(scan_id);

CREATE TABLE subscriptions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    plan VARCHAR(32) NOT NULL DEFAULT 'free',
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    monthly_limit INTEGER NOT NULL DEFAULT 25,
    period_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(80) NOT NULL,
    prefix VARCHAR(16) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_api_keys_user_id ON api_keys(user_id);
