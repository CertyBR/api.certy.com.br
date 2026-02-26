CREATE TABLE IF NOT EXISTS acme_accounts (
    directory_url TEXT PRIMARY KEY,
    contact_email TEXT,
    account_credentials_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS acme_accounts_updated_at_idx
    ON acme_accounts (updated_at DESC);
