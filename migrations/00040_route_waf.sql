-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig40_up;
CREATE PROCEDURE hpg_mig40_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_enabled') THEN
        ALTER TABLE routes ADD COLUMN waf_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER rate_key;
    END IF;
    -- Blocking off = detection-only (CRS logs, never blocks) - safe default.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_blocking') THEN
        ALTER TABLE routes ADD COLUMN waf_blocking TINYINT(1) NOT NULL DEFAULT 0 AFTER waf_enabled;
    END IF;
    -- Per-route seclang escape hatch (rule exclusions) appended before CRS.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_directives') THEN
        ALTER TABLE routes ADD COLUMN waf_directives TEXT NULL AFTER waf_blocking;
    END IF;
END;
CALL hpg_mig40_up();
DROP PROCEDURE hpg_mig40_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig40_down;
CREATE PROCEDURE hpg_mig40_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_directives') THEN
        ALTER TABLE routes DROP COLUMN waf_directives;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_blocking') THEN
        ALTER TABLE routes DROP COLUMN waf_blocking;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_enabled') THEN
        ALTER TABLE routes DROP COLUMN waf_enabled;
    END IF;
END;
CALL hpg_mig40_down();
DROP PROCEDURE hpg_mig40_down;
-- +goose StatementEnd
