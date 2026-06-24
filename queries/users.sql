-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ? LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ? LIMIT 1;

-- name: CreateUser :execresult
INSERT INTO users (email, password_hash, role, full_name, is_active)
VALUES (?, ?, ?, ?, 1);

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login_at = NOW() WHERE id = ?;

-- name: SetUserTOTP :exec
UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?;
