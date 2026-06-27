-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig101_up;
CREATE PROCEDURE hpg_mig101_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='api_keys' AND COLUMN_NAME='use_count') THEN
        ALTER TABLE api_keys ADD COLUMN use_count BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER last_used_ip;
    END IF;
END;
CALL hpg_mig101_up();
DROP PROCEDURE IF EXISTS hpg_mig101_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_keys DROP COLUMN IF EXISTS use_count;
-- +goose StatementEnd
