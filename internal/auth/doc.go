// Package auth handles password hashing (Argon2id), sessions, TOTP 2FA,
// recovery codes, and API key issue/verify.
//
// Conventions:
//   - Password hashes never returned by repos; auth service compares.
//   - Sessions: signed cookie + Redis-backed server side, rotated on login.
//   - API keys: stored only as Argon2id hash; plain shown to user once.
package auth
