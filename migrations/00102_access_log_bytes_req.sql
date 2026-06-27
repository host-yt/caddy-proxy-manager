-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig102_up;
CREATE PROCEDURE hpg_mig102_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log' AND COLUMN_NAME='bytes_req') THEN
        ALTER TABLE host_access_log ADD COLUMN bytes_req BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER bytes_resp;
    END IF;
END;
CALL hpg_mig102_up();
DROP PROCEDURE hpg_mig102_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE host_access_log DROP COLUMN IF EXISTS bytes_req;
-- +goose StatementEnd
