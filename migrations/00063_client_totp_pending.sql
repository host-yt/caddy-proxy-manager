-- +goose Up
-- +goose StatementBegin

-- Short-lived TOTP enrollment stash for the client portal.
-- Mirrors the Redis key used by the admin path (totp:enroll:<id>)
-- but stores it in DB so ClientHandlers doesn't need a Redis client.
-- Secret is stored encrypted at rest (installstate key), same as totp_secret_enc.
-- totp_pending_exp: enrollment window; totp_pending_attempts caps confirm guesses.

DROP PROCEDURE IF EXISTS hpg_mig63_up;
CREATE PROCEDURE hpg_mig63_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_pending_secret') THEN
        ALTER TABLE users ADD COLUMN totp_pending_secret VARBINARY(255) NULL AFTER totp_enabled;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_pending_exp') THEN
        ALTER TABLE users ADD COLUMN totp_pending_exp DATETIME NULL AFTER totp_pending_secret;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_pending_attempts') THEN
        ALTER TABLE users ADD COLUMN totp_pending_attempts INT NOT NULL DEFAULT 0 AFTER totp_pending_exp;
    END IF;
END;
CALL hpg_mig63_up();
DROP PROCEDURE hpg_mig63_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig63_down;
CREATE PROCEDURE hpg_mig63_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_pending_attempts') THEN
        ALTER TABLE users DROP COLUMN totp_pending_attempts;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_pending_exp') THEN
        ALTER TABLE users DROP COLUMN totp_pending_exp;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='totp_pending_secret') THEN
        ALTER TABLE users DROP COLUMN totp_pending_secret;
    END IF;
END;
CALL hpg_mig63_down();
DROP PROCEDURE hpg_mig63_down;
-- +goose StatementEnd
