ALTER TABLE invitations ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now();