-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig39_up;
CREATE PROCEDURE hpg_mig39_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_enabled') THEN
        ALTER TABLE routes ADD COLUMN rate_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER health_passive_max_fail;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_window') THEN
        ALTER TABLE routes ADD COLUMN rate_window VARCHAR(16) NULL AFTER rate_enabled;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_max_events') THEN
        ALTER TABLE routes ADD COLUMN rate_max_events INT NULL AFTER rate_window;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_key') THEN
        ALTER TABLE routes ADD COLUMN rate_key VARCHAR(128) NULL AFTER rate_max_events;
    END IF;
END;
CALL hpg_mig39_up();
DROP PROCEDURE hpg_mig39_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig39_down;
CREATE PROCEDURE hpg_mig39_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_key') THEN
        ALTER TABLE routes DROP COLUMN rate_key;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_max_events') THEN
        ALTER TABLE routes DROP COLUMN rate_max_events;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_window') THEN
        ALTER TABLE routes DROP COLUMN rate_window;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='rate_enabled') THEN
        ALTER TABLE routes DROP COLUMN rate_enabled;
    END IF;
END;
CALL hpg_mig39_down();
DROP PROCEDURE hpg_mig39_down;
-- +goose StatementEnd
