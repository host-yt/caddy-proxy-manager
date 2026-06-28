-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig112_up;
CREATE PROCEDURE hpg_mig112_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_response_code') THEN
        ALTER TABLE routes ADD COLUMN geo_response_code INT NOT NULL DEFAULT 403 AFTER geo_countries;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_fail_closed') THEN
        ALTER TABLE routes ADD COLUMN geo_fail_closed TINYINT(1) NOT NULL DEFAULT 0 AFTER geo_response_code;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_allow_cidrs') THEN
        ALTER TABLE routes ADD COLUMN geo_allow_cidrs TEXT NOT NULL DEFAULT '' AFTER geo_fail_closed;
    END IF;
END;
CALL hpg_mig112_up();
DROP PROCEDURE IF EXISTS hpg_mig112_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig112_down;
CREATE PROCEDURE hpg_mig112_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_allow_cidrs') THEN
        ALTER TABLE routes DROP COLUMN geo_allow_cidrs;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_fail_closed') THEN
        ALTER TABLE routes DROP COLUMN geo_fail_closed;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_response_code') THEN
        ALTER TABLE routes DROP COLUMN geo_response_code;
    END IF;
END;
CALL hpg_mig112_down();
DROP PROCEDURE IF EXISTS hpg_mig112_down;
-- +goose StatementEnd
