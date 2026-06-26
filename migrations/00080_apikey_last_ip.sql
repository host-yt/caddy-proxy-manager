-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig80_up;
CREATE PROCEDURE hpg_mig80_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='api_keys'
                     AND COLUMN_NAME='last_used_ip') THEN
        ALTER TABLE api_keys ADD COLUMN last_used_ip VARCHAR(45) NOT NULL DEFAULT '' AFTER last_used_at;
    END IF;
END;
CALL hpg_mig80_up();
DROP PROCEDURE IF EXISTS hpg_mig80_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig80_down;
CREATE PROCEDURE hpg_mig80_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='api_keys'
                 AND COLUMN_NAME='last_used_ip') THEN
        ALTER TABLE api_keys DROP COLUMN last_used_ip;
    END IF;
END;
CALL hpg_mig80_down();
DROP PROCEDURE IF EXISTS hpg_mig80_down;

-- +goose StatementEnd
