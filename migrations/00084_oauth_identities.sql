-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig84_up;
CREATE PROCEDURE hpg_mig84_up()
BEGIN
    -- Normalises multi-provider OAuth into its own table so a user can
    -- link GitHub, Google, and an OIDC IdP without conflicts.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='oauth_identities') THEN
        CREATE TABLE oauth_identities (
          id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id    BIGINT UNSIGNED NOT NULL,
          provider   VARCHAR(32)  NOT NULL,
          subject    VARCHAR(255) NOT NULL,
          email      VARCHAR(255) NULL,
          -- issuer scopes subject uniqueness; subjects are only unique per-issuer.
          issuer     VARCHAR(255) NOT NULL DEFAULT '',
          linked_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY uq_oauth_identity (provider, issuer, subject),
          KEY idx_oauth_user (user_id),
          CONSTRAINT fk_oai_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    -- password_set: true only when the user has set/reset a real password.
    -- Default 0; backfill sets 1 for users who have a password_hash AND are
    -- not OIDC-only (oidc_subject present + no other indicator of a real password
    -- cannot be distinguished at backfill time, so we use: hash non-empty AND
    -- oidc_subject IS NULL/empty as a safe proxy for "real password").
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='password_set') THEN
        ALTER TABLE users ADD COLUMN password_set TINYINT(1) NOT NULL DEFAULT 0;
        -- Only credit password to users whose hash exists and who are NOT
        -- OIDC-only provisioned (oidc_subject NULL/empty = they set a password
        -- themselves or were created by an admin with a real password).
        UPDATE users SET password_set = 1
        WHERE password_hash != ''
          AND (oidc_subject IS NULL OR oidc_subject = '');
    END IF;
END;
CALL hpg_mig84_up();
DROP PROCEDURE hpg_mig84_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig84_down;
CREATE PROCEDURE hpg_mig84_down()
BEGIN
    DROP TABLE IF EXISTS oauth_identities;

    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='password_set') THEN
        ALTER TABLE users DROP COLUMN password_set;
    END IF;
END;
CALL hpg_mig84_down();
DROP PROCEDURE hpg_mig84_down;
-- +goose StatementEnd
