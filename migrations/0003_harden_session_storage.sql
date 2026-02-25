ALTER TABLE certificate_sessions
    DROP COLUMN IF EXISTS certificate_pem,
    DROP COLUMN IF EXISTS private_key_pem;

CREATE TABLE IF NOT EXISTS certificate_session_events (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    email TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS certificate_session_events_session_id_idx
    ON certificate_session_events (session_id);

CREATE INDEX IF NOT EXISTS certificate_session_events_created_at_idx
    ON certificate_session_events (created_at DESC);
