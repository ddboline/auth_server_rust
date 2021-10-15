CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE session_values (
    id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id),
    session_key TEXT NOT NULL,
    session_value JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE(session_id, session_key)
);

ALTER TABLE sessions ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE sessions ALTER COLUMN email TYPE TEXT;
ALTER TABLE invitations ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE invitations ALTER COLUMN email TYPE TEXT;
ALTER TABLE sessions DROP COLUMN session_data;