# Gauth - A Plug-and-Play Authentication Library for Go

**Gauth** is a simple, plug-and-play authentication library for Go that streamlines the setup of authentication and rate-limiting with minimal configuration. You can integrate it into your Go applications faster than you can say "two-factor authentication."

## Features:
- **Plug-and-Play Setup**: Easily integrate Gauth into your Go application with minimal configuration, and start securing your app in no time. (It’s like putting a password lock on your house, but for your code!)
- **Multi-Database Support**: Works with both PostgreSQL and SQLite for flexible data storage. Whether you're dealing with a tiny database or a full-blown enterprise solution, Gauth’s got you covered.
- **Email Verification**: Secure your account setup with email verification. We’ve got SMTP integration too, so feel free to connect with services like SendGrid. (Because who doesn’t love a little inbox confirmation?)
- **OAuth Integration**: Make your life easier (and your users' login experience smoother) by connecting third-party authentication providers like Google, GitHub, and Facebook. Everyone loves the "Login with Google" button.
- **Authentication & Rate-Limiting Middleware**: Protect your application from brute-force attacks with pre-configured middleware. (Remember, rate-limiting is your app’s bouncer at the club: no one gets in too many times without the right credentials!)
- **Custom Logging & Webhook Support**: Want to track authentication events or set up custom logging? We got you. Webhooks are also included for notifications and event tracking. (Because who doesn't like an app that sends a "you’ve been logged in" message?)

## Installation

To install Gauth, simply run the following Go command:

```bash
go get github.com/scott-mescudi/gauth
```

Once installed, import Gauth into your Go project with:

```go
import "github.com/scott-mescudi/gauth"
```

Make sure your Go version is **1.21** or later—Gauth won’t run on Go 1.20, so no excuses!

## Configuration

To get the most out of **Gauth**, we’ve made configuring your authentication system as easy as possible. Just define a few settings in the `GauthConfig` struct and you’re good to go.

Here's the main Gauth configuration struct:

```go
type GauthConfig struct {
    // Database configuration for user authentication.
    Database         *Database  `validate:"required"`

    // JwtConfig holds JWT settings for token issuance and validation.
    JwtConfig        *JwtConfig `validate:"required"`

    // OauthConfig for third-party authentication (optional).
    OauthConfig      *OauthConfig

    // Enable/disable email/password authentication.
    EmailAndPassword bool

    // EmailConfig for email verification settings (optional).
    EmailConfig      *EmailConfig

    // Cookie settings for session management.
    Cookie           *http.Cookie

    // Webhook settings for event notifications.
    Webhook          *WebhookConfig

    // RateLimitConfig to protect your application.
    RateLimitConfig  *RateLimitConfig

    // Fingerprinting for new device login alerts.
    Fingerprinting   bool

    // Logger for tracking authentication events.
    Logger           logger.GauthLogger

    // Internal list of API routes.
    routes           []Route
}
```

**Woah, that’s a lot!** But don’t worry, we’re breaking it down—let’s dive deeper into each option.

### Database: Storing Users 

Every user management system needs a database. Otherwise, where are you storing your users?

To add a database, you’ll need to configure the `Database` struct:

```go
type Database struct {
    // Driver specifies the database driver (e.g., "mysql", "postgres", "sqlite", "mongodb").
    Driver string      `validate:"required"`

    // Dsn is the Data Source Name (DSN) used for the database connection.
    Dsn    string      `validate:"required"`

    // Config is optional for managing connection pooling.
    Config *PoolConfig
}
```

You can also set up connection pooling by configuring the `PoolConfig` struct. Here’s how:

```go
type PoolConfig struct {
    // MaxConns specifies the maximum number of database connections allowed.
    MaxConns        int           `validate:"gte=1"`

    // MinConns specifies the minimum number of database connections to maintain in the pool.
    MinConns        int           `validate:"gte=0"`

    // MaxConnLifetime defines the maximum lifespan of a connection before it closes.
    MaxConnLifetime time.Duration `validate:"gte=0"`

    // MaxConnIdleTime defines the maximum idle time before a connection is closed.
    MaxConnIdleTime time.Duration `validate:"gte=0"`
}
```

#### Gauth’s Table Setup: Don’t Worry, We Won’t Break Anything (We Promise)

Gauth uses your database to manage users, but don’t worry, we won’t just leave tables lying around all willy-nilly. We create a few tables, and they’re well-organized (We hope). Here’s an example for PostgreSQL:

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS gauth_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
    verificaton_item TEXT,
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
```
