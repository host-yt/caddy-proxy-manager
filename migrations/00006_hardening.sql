-- +goose Up
-- +goose StatementBegin
-- Node approval workflow: auto-joined nodes land disabled and pending approval.
ALTER TABLE caddy_nodes
  ADD COLUMN approved_at  TIMESTAMP NULL AFTER is_enabled,
  ADD COLUMN approved_by  BIGINT UNSIGNED NULL AFTER approved_at,
  ADD COLUMN fingerprint  VARCHAR(128) NULL AFTER approved_by;

-- API keys: switch hot-path verify from Argon2id to HMAC-SHA256 (~100,000x
-- faster); also gain expires_at for short-lived bearer tokens.
ALTER TABLE api_keys
  ADD COLUMN key_hmac    VARCHAR(64) NULL AFTER key_hash,
  ADD COLUMN expires_at  TIMESTAMP NULL AFTER revoked_at,
  ADD KEY idx_ak_hmac (key_hmac),
  ADD KEY idx_ak_expires (expires_at);

-- TOTP secret moves to ciphertext at rest (AES-256-GCM via APP_SECRET HKDF).
-- New column added alongside the old one so a runtime migration can re-encrypt
-- on next successful TOTP verify.
ALTER TABLE users
  ADD COLUMN totp_secret_enc TEXT NULL AFTER totp_secret;

-- Drift detection columns on routes.
ALTER TABLE routes
  ADD COLUMN last_pushed_at   TIMESTAMP NULL AFTER updated_at,
  ADD COLUMN last_pushed_hash CHAR(64) NULL AFTER last_pushed_at,
  ADD KEY idx_route_node_status (caddy_node_id, status);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE routes
  DROP INDEX idx_route_node_status,
  DROP COLUMN last_pushed_hash,
  DROP COLUMN last_pushed_at;

ALTER TABLE users
  DROP COLUMN totp_secret_enc;

ALTER TABLE api_keys
  DROP INDEX idx_ak_expires,
  DROP INDEX idx_ak_hmac,
  DROP COLUMN expires_at,
  DROP COLUMN key_hmac;

ALTER TABLE caddy_nodes
  DROP COLUMN fingerprint,
  DROP COLUMN approved_by,
  DROP COLUMN approved_at;
-- +goose StatementEnd
