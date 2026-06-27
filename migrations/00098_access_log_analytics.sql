-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig98_up;
CREATE PROCEDURE hpg_mig98_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log' AND COLUMN_NAME='bytes_resp') THEN
        ALTER TABLE host_access_log ADD COLUMN bytes_resp BIGINT UNSIGNED NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log' AND COLUMN_NAME='proto') THEN
        ALTER TABLE host_access_log ADD COLUMN proto VARCHAR(8) NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log' AND COLUMN_NAME='country') THEN
        ALTER TABLE host_access_log ADD COLUMN country CHAR(2) NOT NULL DEFAULT '';
    END IF;
END;
CALL hpg_mig98_up();
DROP PROCEDURE hpg_mig98_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE host_access_log
    DROP COLUMN IF EXISTS bytes_resp,
    DROP COLUMN IF EXISTS proto,
    DROP COLUMN IF EXISTS country;
-- +goose StatementEnd
