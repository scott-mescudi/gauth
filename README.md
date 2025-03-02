# gauth - A Golang Authentication Library

## Features Checklist

### Session Management
- [x] Handled with JWTs

### Anonymous Login
- [ ] Allow users to access without authentication

### OAuth Support
- [ ] GitHub login
- [ ] Google login
- [ ] Apple login
- [ ] Discord login
- [ ] LinkedIn login
- [ ] X (Twitter) login
- [ ] Microsoft login
- [ ] Facebook login

### Email & Password Authentication
- [x] Supports email verification
- [x] Easy integration with email providers

### Account Management
- [ ] Update accounts (email-based authentication)
- [ ] Remove accounts (email-based authentication)

### Passkey Support
- [ ] Secure passwordless authentication

### Custom Database Schema
- [x] Plug-and-play setup
- [x] Automatically creates required tables

### Profile Picture Support
- [ ] Stores images as Base64

### Login Rate Limiters
- [ ] Prevent brute-force attacks

### Multi-Level Privilege Support
- [ ] Role-based access control

### Auth Middleware
- [x] Secure routes easily

### Refresh & Access Token Support
- [x] Available via cookies
- [x] Available via JSON

### User Validation Endpoint
- [ ] Check if a user or JWT is valid

### Webhook Support
- [ ] Trigger actions on authentication events

## Possible Features (Future Considerations)

- [ ] Device Fingerprinting (requires frontend support)