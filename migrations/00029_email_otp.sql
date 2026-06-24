-- +goose Up
-- +goose StatementBegin

-- Email OTP as second factor (per-user opt-in).
-- email_otp_enabled: user has enrolled Email as 2FA method.
-- Pending hash/exp columns mirror the SMS OTP pattern used in mig 26 so the
-- ClientHandlers enrollment flow stays free of redis dependencies.

DROP PROCEDURE IF EXISTS hpg_mig29_up;
CREATE PROCEDURE hpg_mig29_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email_otp_enabled') THEN
        ALTER TABLE users ADD COLUMN email_otp_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER sms_otp_pending_exp;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email_otp_pending_hash') THEN
        ALTER TABLE users ADD COLUMN email_otp_pending_hash VARCHAR(64) NULL AFTER email_otp_enabled;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email_otp_pending_exp') THEN
        ALTER TABLE users ADD COLUMN email_otp_pending_exp DATETIME NULL AFTER email_otp_pending_hash;
    END IF;
END;
CALL hpg_mig29_up();
DROP PROCEDURE hpg_mig29_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig29_down;
CREATE PROCEDURE hpg_mig29_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email_otp_pending_exp') THEN
        ALTER TABLE users DROP COLUMN email_otp_pending_exp;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email_otp_pending_hash') THEN
        ALTER TABLE users DROP COLUMN email_otp_pending_hash;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='email_otp_enabled') THEN
        ALTER TABLE users DROP COLUMN email_otp_enabled;
    END IF;
END;
CALL hpg_mig29_down();
DROP PROCEDURE hpg_mig29_down;
-- +goose StatementEnd
