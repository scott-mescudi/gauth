CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE gauth_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    birth_date DATE,
    address TEXT,
    profile_picture TEXT DEFAULT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user', 'moderator', 'guest')),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted', 'disabled')),
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE gauth_user_verification (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    verification_type VARCHAR(50) NOT NULL,  -- 'email' or 'phone' etc.
    verification_token TEXT NOT NULL,
    token_expiry TIMESTAMP NOT NULL,
    isverified BOOLEAN DEFAULT FALSE,
);


CREATE TABLE gauth_user_auth (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    last_login TIMESTAMP NULL,
    last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_provider VARCHAR(50) DEFAULT NULL,
    auth_id VARCHAR(255) DEFAULT NULL,
    refresh_token TEXT DEFAULT NULL,
);

CREATE TABLE gauth_user_preferences (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    preferences JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}'
);
