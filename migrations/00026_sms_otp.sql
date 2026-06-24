-- +goose Up
-- +goose StatementBegin

-- SMS OTP as second factor (per-user opt-in, admin-gated).
-- sms_otp_enabled: user has enrolled SMS as 2FA method.
-- sms_otp_available in settings: admin must explicitly enable before clients can opt in.

DROP PROCEDURE IF EXISTS hpg_mig26_up;
CREATE PROCEDURE hpg_mig26_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sms_otp_enabled') THEN
        ALTER TABLE users ADD COLUMN sms_otp_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER totp_enabled;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sms_otp_pending_hash') THEN
        ALTER TABLE users ADD COLUMN sms_otp_pending_hash VARCHAR(64) NULL AFTER sms_otp_enabled;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sms_otp_pending_exp') THEN
        ALTER TABLE users ADD COLUMN sms_otp_pending_exp DATETIME NULL AFTER sms_otp_pending_hash;
    END IF;

    -- Seed admin-controlled flags (INSERT IGNORE = idempotent).
    INSERT IGNORE INTO settings (`key`, value, is_encrypted)
        VALUES ('sms_otp_available', '0', 0);
    INSERT IGNORE INTO settings (`key`, value, is_encrypted)
        VALUES ('oidc.password_login_disabled', '0', 0);
END;
CALL hpg_mig26_up();
DROP PROCEDURE hpg_mig26_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig26_down;
CREATE PROCEDURE hpg_mig26_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sms_otp_pending_exp') THEN
        ALTER TABLE users DROP COLUMN sms_otp_pending_exp;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sms_otp_pending_hash') THEN
        ALTER TABLE users DROP COLUMN sms_otp_pending_hash;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sms_otp_enabled') THEN
        ALTER TABLE users DROP COLUMN sms_otp_enabled;
    END IF;
    DELETE FROM settings WHERE `key` IN ('sms_otp_available', 'oidc.password_login_disabled');
END;
CALL hpg_mig26_down();
DROP PROCEDURE hpg_mig26_down;
-- +goose StatementEnd
