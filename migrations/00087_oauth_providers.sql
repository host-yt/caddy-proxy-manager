-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig87_up;
CREATE PROCEDURE hpg_mig87_up()
BEGIN
    -- Per-provider OAuth2 credentials (GitHub, Google, ...) for the
    -- multi-provider social login that runs ALONGSIDE the OIDC flow. Kept
    -- separate from the `settings` table so each provider is one tidy row.
    -- client_secret is stored AES-GCM encrypted (is_encrypted=1); never plaintext.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='oauth_providers') THEN
        CREATE TABLE oauth_providers (
          provider       VARCHAR(32)  NOT NULL PRIMARY KEY,
          enabled        TINYINT(1)   NOT NULL DEFAULT 0,
          client_id      VARCHAR(255) NOT NULL DEFAULT '',
          -- AES-GCM ciphertext (base64). Empty string means "no secret stored".
          client_secret  TEXT         NULL,
          is_encrypted   TINYINT(1)   NOT NULL DEFAULT 1,
          -- space-separated extra scopes; empty falls back to a per-provider default.
          scopes         VARCHAR(255) NOT NULL DEFAULT '',
          -- auto-create a local account on first login by this provider.
          auto_provision TINYINT(1)   NOT NULL DEFAULT 0,
          default_role   VARCHAR(32)  NOT NULL DEFAULT 'support',
          created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig87_up();
DROP PROCEDURE IF EXISTS hpg_mig87_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig87_down;
CREATE PROCEDURE hpg_mig87_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='oauth_providers') THEN
        DROP TABLE oauth_providers;
    END IF;
END;
CALL hpg_mig87_down();
DROP PROCEDURE IF EXISTS hpg_mig87_down;
-- +goose StatementEnd
