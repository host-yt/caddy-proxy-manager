-- +goose Up
-- +goose StatementBegin
-- What each node actually holds: the last config hash a /load accepted and the
-- last push error. The compile badge (00149) only says what the panel built.
DROP PROCEDURE IF EXISTS hpg_mig163_up;
CREATE PROCEDURE hpg_mig163_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_applied_hash') THEN
        ALTER TABLE caddy_nodes ADD COLUMN config_applied_hash VARCHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_applied_at') THEN
        ALTER TABLE caddy_nodes ADD COLUMN config_applied_at DATETIME NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_apply_error') THEN
        ALTER TABLE caddy_nodes ADD COLUMN config_apply_error TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_apply_error_at') THEN
        ALTER TABLE caddy_nodes ADD COLUMN config_apply_error_at DATETIME NULL;
    END IF;
END;
CALL hpg_mig163_up();
DROP PROCEDURE IF EXISTS hpg_mig163_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig163_down;
CREATE PROCEDURE hpg_mig163_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_applied_hash') THEN
        ALTER TABLE caddy_nodes DROP COLUMN config_applied_hash;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_applied_at') THEN
        ALTER TABLE caddy_nodes DROP COLUMN config_applied_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_apply_error') THEN
        ALTER TABLE caddy_nodes DROP COLUMN config_apply_error;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='config_apply_error_at') THEN
        ALTER TABLE caddy_nodes DROP COLUMN config_apply_error_at;
    END IF;
END;
CALL hpg_mig163_down();
DROP PROCEDURE IF EXISTS hpg_mig163_down;
-- +goose StatementEnd
