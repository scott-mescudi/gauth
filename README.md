# Gauth - A Plug-and-Play Authentication Library for Go

**Gauth** is a simple, plug-and-play authentication library for Go that streamlines the setup of authentication and rate-limiting with minimal configuration. You can integrate it into your Go applications faster than you can say "two-factor authentication."

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Database Configuration](#database-storing-users)
  - [JWT Configuration](#jwtconfig---your-apps-bouncer)
  - [Email and Password Authentication](#email-and-password-authentication-the-classic-approach-but-with-extra-security)
  - [Email Configuration](#emailconfig-the-email-magic)
  - [OAuth](#oauth)
  - [Cookies](#cookies)
  - [Webhooks](#webhooks)
  - [Logging](#logging)
  - [Fingerprinting](#fingerprinting)
  - [Rate Limiting](#ratelimitconfig)
- [Usage](#usage)

## Features:

- **Plug-and-Play Setup**: Easily integrate Gauth into your Go application with minimal configuration, and start securing your app in no time.
- **Multi-Database Support**: Works with both PostgreSQL and SQLite for flexible data storage. Whether you're dealing with a tiny database or a full-blown enterprise solution, Gauth’s got you covered. (Because even databases need a little love and attention.)
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

    // Enable/disable email/password authentication.
    EmailAndPassword bool

    // OauthConfig for third-party authentication (optional).
    OauthConfig      *OauthConfig

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

---

### JwtConfig - Your app's bouncer

Gauth uses JWT-based authentication. It’s like a VIP pass for your app: only the right people get access. Plus, it’s a compact, self-contained token that helps you avoid unnecessary database lookups.

Before we get into the code, here’s a quick reminder: A JWT (JSON Web Token) consists of three parts: Header, Payload, and Signature.

Gauth allows you to configure JWT settings through the `JwtConfig` struct:

```go
// JwtConfig defines settings for JSON Web Token (JWT) authentication.
type JwtConfig struct {
	// Issuer specifies the entity that issues the JWT.
	Issuer                 string        `validate:"required"`

	// Secret is the secret key used for signing JWTs.
	Secret                 []byte        `validate:"required"`

	// AccessTokenExpiration defines the expiration duration for access tokens.
	AccessTokenExpiration  time.Duration `validate:"required,gt=0"`

	// RefreshTokenExpiration defines the expiration duration for refresh tokens.
	RefreshTokenExpiration time.Duration `validate:"required,gt=0"`
}
```

## Email and Password Authentication: The Classic Approach (But With Extra Security)

Remember the good ol' days of just needing an email and password to access your account? Well, we've added a bit more to it because we like to keep things secure! With **Email and Password Authentication**, you can offer users the ability to log in the way they’ve always done, but with all the latest security enhancements, like email verification.

If you don’t need email verification (we won’t judge), you can turn off verification emails, and Gauth will simply authenticate users based on their credentials. That’s the beauty of simplicity, right? But we’re all about making things secure, so we also give you the option to configure email verification.

### Enabling Email and Password Authentication

To enable email and password authentication, just set the `EmailAndPassword` flag in your `GauthConfig` struct to `true`. This will allow the classic email and password login functionality.

But hey, if you want extra layers, we’ve got you covered. You can enable **Email Verification** for things like account creation, password updates, or email changes. Let’s take a look at the configuration.

---

### EmailConfig: The Email Magic

Here’s where you configure email services for authentication and verification. You can specify which email provider you want to use—because why send emails the boring way when you can have fun with cool providers like SendGrid or SMTP?

```go
// EmailConfig holds the configuration required for email-based authentication and verification.
type EmailConfig struct {
	// Provider specifies the email service provider to use.
	Provider       email.EmailProvider  `validate:"required"` // Pick your favorite provider! (Not a fan of email? We don’t judge)

	// AppDomain specifies the domain name of the application sending emails.
	AppDomain      string               `validate:"required"` // Because your app has to live somewhere, right?

	// RedirectConfig holds the configuration for redirecting users after email verification.
	RedirectConfig *RedirectConfig      `validate:"required"`

	// TemplateConfig holds email templates for authentication flows (optional).
	TemplateConfig *EmailTemplateConfig
}
```

---

### Pick Your Email Provider

Gauth supports several email providers, including **SMTP** and **SendGrid**, so you can send emails with a touch of style.

Here’s how you can set up an SMTP client:

```go
// SMTP Client (Yes, you can use Gmail too!)
smtpClient := email.NewSMTPClient("smtp.gmail.com", "587", "gauth@gauth.com", "superSecurePassword")
```

Or, if you’re feeling like a pro, use **SendGrid**:

```go
// SendGrid Client
sendGridClient := email.NewSendGridClient("scott", "gauth@sendgrid.com", "secretApiKey")
```

If you’re feeling extra adventurous, you can even create your own custom email provider by implementing the `EmailProvider` interface.

```go
// Custom Email Provider: Build it, and they will come (or email).
type EmailProvider interface {
    SendEmail(toEmail, toName, verificationURL, tpl string) error
}
```

---

### RedirectConfig: The "I Need To Go Somewhere" Part

Once your users have clicked on the verification link, where should they go? This is where you set up your redirection URLs after email verification.

```go
// RedirectConfig defines redirection URLs after completing authentication steps.
type RedirectConfig struct {
	// SignupComplete is the URL to redirect users after signup verification.
	SignupComplete string `validate:"required,url"`

	// EmailSet is the URL to redirect users after setting their email.
	EmailSet string `validate:"required,url"`

	// PasswordSet is the URL to redirect users after updating their password.
	PasswordSet string `validate:"required,url"`

	// UsernameSet is the URL to redirect users after setting their username.
	UsernameSet string `validate:"required,url"`
}
```

Because, let’s face it, you don’t want your users to click a verification link and then get stuck in some void. You need to give them a path forward. Make sure to configure those redirect URLs so they don’t end up wandering in the digital wilderness.

---

### Custom Email Templates

If you want to impress your users (and we know you do), you can use custom email templates for things like **Signup**, **Password Reset**, and **Account Deletion**. Who says security emails can’t look nice?

Here’s an example of a **Signup Template**:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Signup Confirmation</title>
  </head>
  <body>
    <h2>Welcome to Our Platform!</h2>
    <p>
      Thank you for signing up! Please click the link below to confirm your
      email address:
    </p>
    <a href="{{.Link}}">Confirm your email</a>
  </body>
</html>
```

Make sure you include {{.Link}} exactly where you want the users to click, as this will dynamically generate the actual verification URL. It’s crucial that this placeholder is placed properly, as it will take users to the right page for verification.

# OAuth

So, you’re tired of basic email and password authentication? (We get it—it's like using dial-up internet when fiber optics exist.) Or maybe you just want to make your app look even cooler by offering OAuth? Well, **Gauth** has you covered!

At the moment, we support **GitHub** and **Google OAuth**, but we’re working hard to add more options.

Here’s how to get OAuth working in your app, with the **OauthConfig** struct you’ll need to configure:

```go
// OauthConfig defines OAuth configurations for multiple providers.
type OauthConfig struct {
	// Domain specifies the domain for OAuth authentication.
	Domain string `validate:"required"`

	// Github holds the OAuth configuration for GitHub.
	Github *Oauth

	// Google holds the OAuth configuration for Google.
	Google *Oauth

    // we'll add more eventually (pinky promise)
}
```

### Step 1: Set Your Domain

Here’s where you get to tell us where your app is living. Yep, we know—it’s like entering your address every time you order pizza. But hey, OAuth needs to know where to show up, right?

Just set the **Domain** field. It’s simple, and you only have to do it once... okay, maybe twice.

### Step 2: Configure Your OAuth Client

Now comes the fun part! Let’s set up the actual OAuth clients for GitHub, Google, or any provider you like in the future. Here’s the struct for that:

```go
// Oauth defines the configuration required for third-party OAuth integrations.
type Oauth struct {
	// ClientID is the OAuth client ID provided by the third-party service.
	ClientID string `validate:"required"`

	// ClientSecret is the OAuth client secret provided by the third-party service.
	ClientSecret string `validate:"required"`
}
```

You’ll need to provide a **ClientID** and **ClientSecret** for each provider.

---

And that’s all you need to get started with OAuth in Gauth! Whether you're allowing users to "Login with GitHub" or "Login with Google," you’re all set to make authentication a breeze.

## Now, let's talk about some advanced configurations!

# Cookies

By default, **Gauth** sends access and refresh tokens to the client via JSON. But did you know we also support using cookies for setting the refresh token? (Because who doesn’t love cookies?) Just configure the **cookie config**, and voilà—your app's tokens are set!

If you enable cookies, **Gauth** will send the access token via JSON and set the refresh token in a cookie.

---

# Webhooks

**Gauth** also supports sending webhooks for authentication-related events like login and signup. Simply configure the struct below, and you’re set to catch all the action:

```go
// WebhookConfig defines settings for integrating webhooks to receive authentication-related events.
type WebhookConfig struct {
	// CallbackURL is the URL where webhook events should be sent.
	CallbackURL string `validate:"required,url"`

	// Method is the HTTP method (POST/GET) used for webhook requests.
	Method string `validate:"required,oneof=POST GET"`

	// AuthHeader is the header key for webhook authentication (optional).
	AuthHeader string

	// AuthHeaderValue is the value for the authentication header (optional).
	AuthHeaderValue string
}
```

Now you can catch the cool events like "User Logged In" or "New Account Created."

---

# Logging

In addition to webhooks, **Gauth** also supports logging every action it takes. It comes with a default logger that uses an `io.Writer`. To use it, just import the logger package and call the `NewDefaultGauthLogger` function:

```go
import "github.com/scott-mescudi/gauth/pkg/logger"
```

Then call the function:

```go
gauthLogger := logger.NewDefaultGauthLogger(os.Stdout)
```

Once that's set up, just pass the logger into the **Gauth** config.

Or, if you’re feeling fancy, you can create your own logger by implementing the **GauthLogger** interface:

```go
type GauthLogger interface {
	Error(msg string)
	Warn(msg string)
	Info(msg string)
	Debug(msg string)
}
```

Now you can customize the logging to suit your needs—whether you're a “quiet observer” or the “debug everything” type.

---

# Fingerprinting

Gauth includes device fingerprinting to enhance security by detecting logins from new devices. When enabled, it triggers a webhook notification whenever a user logs in from an unrecognized device. To activate this feature, simply set the `Fingerprinting` flag to `true` in your configuration.

# Rate Limiting

To protect your authentication endpoints from abuse and brute-force attacks, Gauth provides built-in rate limiting through the `RateLimitConfig`. This configuration allows you to set separate limits for authentication routes and account update routes.

```go
// RateLimitConfig defines rate-limiting configurations for authentication and account update routes.
type RateLimitConfig struct {
    // AuthLimit defines rate limits for authentication routes (e.g., login, signup).
    AuthLimit *Limit

    // UpdateLimit defines rate limits for account update routes (e.g., email, username, password).
    UpdateLimit *Limit
}
```

The configuration supports two types of rate limiters:

1. **Authentication Rate Limiter**: Controls access to login and signup endpoints
2. **Update Rate Limiter**: Manages requests for account modifications like email, username, and password changes

Configure these rate limiters using the `Limit` struct:

```go
// Limit defines rate-limiting configurations, such as token count and cooldown periods.
type Limit struct {
	// TokenCount specifies the number of tokens a user has before hitting the rate limit.
	TokenCount int `validate:"gte=1"`

	// CooldownPeriod specifies the duration a user must wait after using all tokens.
	CooldownPeriod time.Duration `validate:"gte=0"`

	// TimeInactive specifies the duration after which the user's activity is considered inactive.
	TimeInactive time.Duration `validate:"gte=0"`

	// CleanupInterval specifies how often to clean up inactive user data.
	CleanupInterval time.Duration `validate:"gte=0"`
}
```

---

Now that we’ve covered all the configurations, you’re probably wondering, _"How do I actually use all of this?"_ Well, don’t worry—it's as easy as setting up a coffee machine!

To make **Gauth** work with your app, all you need to do is call the **ParseConfig** function. This function takes in the config struct you just created and your `http.ServeMux`. It will then parse the config and bind the necessary routes to your `ServeMux`. Simple, right?

This function returns two things: a "clean" function (for cleaning up resources like database connections or rate limiters) and an error (because, let’s face it, errors happen sometimes—no one’s perfect).

Here’s what it looks like:

```go
clean, err := gauth.ParseConfig(config, mux)
if err != nil {
    log.Fatalln(err)
}
defer clean()
```

---

### Want to See the Routes **Gauth** Registered?

If you're curious to see all the routes **Gauth** has registered on your `ServeMux`, you can call the **.GetRoutes()** method on the config struct. This will give you a list of all the routes.

```go
config.GetRoutes()
```

This will return an array of routes. And here’s what each route looks like:

```go
// Route defines an API route for the authentication system.
type Route struct {
	// Method specifies the HTTP method (GET, POST, etc.).
	Method string

	// Path specifies the API path for the route.
	Path string

	// Handler specifies the handler function for the route.
	Handler string

	// Description provides a description of what the route does.
	Description string
}
```
