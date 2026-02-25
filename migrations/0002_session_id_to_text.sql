ALTER TABLE certificate_sessions
    ALTER COLUMN id TYPE TEXT USING id::text;
