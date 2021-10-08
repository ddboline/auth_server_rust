ALTER TABLE sessions ADD COLUMN secret_key TEXT NOT NULL DEFAULT md5(random()::text);
