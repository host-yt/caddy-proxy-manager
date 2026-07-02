-- +goose Up
-- +goose StatementBegin
-- Gate self-registered accounts behind email ownership proof. Without this an
-- attacker self-registers victim@corp (is_active=1, no verification) and an
-- OAuth/OIDC-by-email adoption later hands them the row. New self-registered
-- rows land email_verified=0; the OAuth-by-email adoption path refuses those.
-- Backfilled to 1 immediately below so every EXISTING user keeps working - only
-- accounts created after this migration can be unverified.
-- Named email_verified (not *_verified_key/_index) to dodge the MySQL->SQLite
-- inline-index transformer trap for length-typed *_key/*_index columns.
ALTER TABLE users
    ADD COLUMN email_verified TINYINT NOT NULL DEFAULT 0;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE users SET email_verified = 1;
-- +goose StatementEnd
-- +goose StatementBegin
-- One-time email-verification tokens for self-registration double opt-in.
-- Mirrors password_resets: store only the sha256 hash, single-use via used_at.
CREATE TABLE email_verifications (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    BIGINT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at    TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_email_verif_token (token_hash),
  KEY idx_email_verif_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS email_verifications;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN email_verified;
-- +goose StatementEnd
