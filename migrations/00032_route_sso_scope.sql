-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig32_up;
CREATE PROCEDURE hpg_mig32_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_paths') THEN
        ALTER TABLE routes ADD COLUMN sso_paths TEXT NULL AFTER sso_trusted_proxies;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_hosts') THEN
        ALTER TABLE routes ADD COLUMN sso_hosts TEXT NULL AFTER sso_paths;
    END IF;
END;
CALL hpg_mig32_up();
DROP PROCEDURE hpg_mig32_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig32_down;
CREATE PROCEDURE hpg_mig32_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_hosts') THEN
        ALTER TABLE routes DROP COLUMN sso_hosts;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_paths') THEN
        ALTER TABLE routes DROP COLUMN sso_paths;
    END IF;
END;
CALL hpg_mig32_down();
DROP PROCEDURE hpg_mig32_down;
-- +goose StatementEnd
