ALTER TABLE certificate_sessions
    ADD COLUMN IF NOT EXISTS email_verification_code_hash TEXT,
    ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS email_verification_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
