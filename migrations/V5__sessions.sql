CREATE TABLE sessions (
    id UUID NOT NULL PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    session_data JSON,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    FOREIGN KEY (email) REFERENCES users(email)
);