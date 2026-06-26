-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig85_up;
CREATE PROCEDURE hpg_mig85_up()
BEGIN
    -- try_duration: total time Caddy may spend retrying across all upstreams (ms).
    -- Default 5000 = 5s, matching previous hardcoded value.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_try_duration_ms') THEN
        ALTER TABLE routes ADD COLUMN lb_try_duration_ms INT NOT NULL DEFAULT 5000 AFTER health_passive_max_fail;
    END IF;
    -- try_interval: delay between retry attempts (ms). Default 250 = 250ms.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_try_interval_ms') THEN
        ALTER TABLE routes ADD COLUMN lb_try_interval_ms INT NOT NULL DEFAULT 250 AFTER lb_try_duration_ms;
    END IF;
END;
CALL hpg_mig85_up();
DROP PROCEDURE IF EXISTS hpg_mig85_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig85_down;
CREATE PROCEDURE hpg_mig85_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_try_interval_ms') THEN
        ALTER TABLE routes DROP COLUMN lb_try_interval_ms;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_try_duration_ms') THEN
        ALTER TABLE routes DROP COLUMN lb_try_duration_ms;
    END IF;
END;
CALL hpg_mig85_down();
DROP PROCEDURE IF EXISTS hpg_mig85_down;
-- +goose StatementEnd
