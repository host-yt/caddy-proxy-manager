-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig55_up;
CREATE PROCEDURE hpg_mig55_up()
BEGIN
    -- Per-peer key rotation schedule and bookkeeping.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='key_rotation_days') THEN
        ALTER TABLE customer_wg_peer
            ADD COLUMN key_rotation_days INT NULL,
            ADD COLUMN last_rotated_at TIMESTAMP NULL,
            ADD COLUMN rotation_alert_sent_at TIMESTAMP NULL;
    END IF;
    -- Plan-level default rotation cadence (NULL = inherit global setting).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='plans' AND COLUMN_NAME='wg_key_rotation_days') THEN
        ALTER TABLE plans ADD COLUMN wg_key_rotation_days INT NULL;
    END IF;
END;
CALL hpg_mig55_up();
DROP PROCEDURE hpg_mig55_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig55_down;
CREATE PROCEDURE hpg_mig55_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='plans' AND COLUMN_NAME='wg_key_rotation_days') THEN
        ALTER TABLE plans DROP COLUMN wg_key_rotation_days;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='key_rotation_days') THEN
        ALTER TABLE customer_wg_peer
            DROP COLUMN rotation_alert_sent_at,
            DROP COLUMN last_rotated_at,
            DROP COLUMN key_rotation_days;
    END IF;
END;
CALL hpg_mig55_down();
DROP PROCEDURE hpg_mig55_down;
-- +goose StatementEnd
