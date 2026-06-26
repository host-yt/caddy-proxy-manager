-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig86_up;
CREATE PROCEDURE hpg_mig86_up()
BEGIN
    -- Per-upstream passive health override. NULL = inherit pool-level settings.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='health_override') THEN
        ALTER TABLE route_upstreams ADD COLUMN health_override TINYINT(1) NULL DEFAULT NULL AFTER enabled;
    END IF;
    -- Max passive fails before this upstream is ejected (NULL = pool default).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='health_max_fails') THEN
        ALTER TABLE route_upstreams ADD COLUMN health_max_fails INT NULL DEFAULT NULL AFTER health_override;
    END IF;
    -- Fail observation window for this upstream in seconds (NULL = pool default).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='health_fail_dur_secs') THEN
        ALTER TABLE route_upstreams ADD COLUMN health_fail_dur_secs INT NULL DEFAULT NULL AFTER health_max_fails;
    END IF;
END;
CALL hpg_mig86_up();
DROP PROCEDURE IF EXISTS hpg_mig86_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig86_down;
CREATE PROCEDURE hpg_mig86_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='health_fail_dur_secs') THEN
        ALTER TABLE route_upstreams DROP COLUMN health_fail_dur_secs;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='health_max_fails') THEN
        ALTER TABLE route_upstreams DROP COLUMN health_max_fails;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='health_override') THEN
        ALTER TABLE route_upstreams DROP COLUMN health_override;
    END IF;
END;
CALL hpg_mig86_down();
DROP PROCEDURE IF EXISTS hpg_mig86_down;
-- +goose StatementEnd
