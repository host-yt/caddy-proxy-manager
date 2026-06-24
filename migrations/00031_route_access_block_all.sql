-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig31_up;
CREATE PROCEDURE hpg_mig31_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='access_block_all') THEN
        ALTER TABLE routes ADD COLUMN access_block_all TINYINT(1) NOT NULL DEFAULT 0 AFTER access_deny;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='maintenance_allow') THEN
        ALTER TABLE routes ADD COLUMN maintenance_allow TEXT NULL AFTER access_block_all;
    END IF;
END;
CALL hpg_mig31_up();
DROP PROCEDURE hpg_mig31_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig31_down;
CREATE PROCEDURE hpg_mig31_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='maintenance_allow') THEN
        ALTER TABLE routes DROP COLUMN maintenance_allow;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='access_block_all') THEN
        ALTER TABLE routes DROP COLUMN access_block_all;
    END IF;
END;
CALL hpg_mig31_down();
DROP PROCEDURE hpg_mig31_down;
-- +goose StatementEnd
