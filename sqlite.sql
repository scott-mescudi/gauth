CREATE TABLE gauth_user (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    signup_method VARCHAR(255) DEFAULT 'plain' CHECK (signup_method IN ('github', 'google', 'microsoft', 'discord', 'plain')),
    last_name VARCHAR(255),
    profile_picture BYTEA DEFAULT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user', 'moderator', 'guest')),
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gauth_user_verification (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    verification_item TEXT,
    verification_type VARCHAR(50) DEFAULT 'none',
    verification_token TEXT,
    token_expiry TIMESTAMP,
    isverified BOOLEAN
);

CREATE TABLE IF NOT EXISTS gauth_user_auth (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    last_login TIMESTAMP,
    last_password_change TIMESTAMP,
    last_email_change TIMESTAMP,
    last_username_change TIMESTAMP,
    auth_provider VARCHAR(50),
    login_fingerprint TEXT,
    auth_id VARCHAR(255),
    refresh_token TEXT DEFAULT NULL
);