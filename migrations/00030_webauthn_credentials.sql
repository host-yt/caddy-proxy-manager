-- +goose Up
-- +goose StatementBegin

-- Passkey / WebAuthn credentials. One row per credential; a user can have
-- multiple (different devices). credential_id is the public RP-side handle.

DROP PROCEDURE IF EXISTS hpg_mig30_up;
CREATE PROCEDURE hpg_mig30_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='webauthn_credentials') THEN
        CREATE TABLE webauthn_credentials (
            id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id       BIGINT UNSIGNED NOT NULL,
            credential_id VARBINARY(255) NOT NULL,
            public_key    VARBINARY(1024) NOT NULL,
            attestation_type VARCHAR(32) DEFAULT '',
            aaguid        VARBINARY(16),
            sign_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
            transports    VARCHAR(255) DEFAULT '',
            backup_eligible TINYINT(1) NOT NULL DEFAULT 0,
            backup_state    TINYINT(1) NOT NULL DEFAULT 0,
            user_present    TINYINT(1) NOT NULL DEFAULT 0,
            user_verified   TINYINT(1) NOT NULL DEFAULT 0,
            name          VARCHAR(120) NOT NULL DEFAULT '',
            last_used_at  DATETIME NULL,
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_webauthn_credential_id (credential_id),
            KEY idx_webauthn_user (user_id),
            CONSTRAINT fk_webauthn_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
    -- Optional column on users to flag accounts that have at least one passkey
    -- (used to short-circuit "username-less" passwordless login UI hints).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='has_passkey') THEN
        ALTER TABLE users ADD COLUMN has_passkey TINYINT(1) NOT NULL DEFAULT 0 AFTER email_otp_pending_exp;
    END IF;
END;
CALL hpg_mig30_up();
DROP PROCEDURE hpg_mig30_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig30_down;
CREATE PROCEDURE hpg_mig30_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='has_passkey') THEN
        ALTER TABLE users DROP COLUMN has_passkey;
    END IF;
    DROP TABLE IF EXISTS webauthn_credentials;
END;
CALL hpg_mig30_down();
DROP PROCEDURE hpg_mig30_down;
-- +goose StatementEnd
