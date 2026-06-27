-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig100_up;
CREATE PROCEDURE hpg_mig100_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='log_rollups' AND COLUMN_NAME='bytes_resp') THEN
        ALTER TABLE log_rollups ADD COLUMN bytes_resp BIGINT UNSIGNED NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig100_up();
DROP PROCEDURE hpg_mig100_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE log_rollups DROP COLUMN IF EXISTS bytes_resp;
-- +goose StatementEnd
