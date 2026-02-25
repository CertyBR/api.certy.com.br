ALTER TABLE certificate_sessions
    ADD COLUMN IF NOT EXISTS email_verification_last_sent_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS email_verification_resend_count INTEGER NOT NULL DEFAULT 0;
