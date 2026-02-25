CREATE TABLE IF NOT EXISTS certificate_sessions (
    id UUID PRIMARY KEY,
    domain TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL,
    dns_records_json JSONB NOT NULL,
    account_credentials_json TEXT NOT NULL,
    order_url TEXT NOT NULL,
    certificate_pem TEXT,
    private_key_pem TEXT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS certificate_sessions_expires_at_idx
    ON certificate_sessions (expires_at);
