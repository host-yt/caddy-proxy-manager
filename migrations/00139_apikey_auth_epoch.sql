-- +goose Up
-- +goose StatementBegin
-- API keys carried no authorization snapshot, so a deactivated/demoted/deleted
-- owner kept full API access while their cookie sessions died at once.
-- Backfilled from the owner so keys issued before this change keep working
-- until the next privilege change.
DROP PROCEDURE IF EXISTS hpg_mig139_up;
CREATE PROCEDURE hpg_mig139_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='api_keys' AND COLUMN_NAME='auth_epoch') THEN
        ALTER TABLE api_keys ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 0;
        UPDATE api_keys
           SET auth_epoch = COALESCE((SELECT u.auth_epoch FROM users u WHERE u.id = api_keys.user_id), 0);
    END IF;
END;
CALL hpg_mig139_up();
DROP PROCEDURE IF EXISTS hpg_mig139_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig139_down;
CREATE PROCEDURE hpg_mig139_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='api_keys' AND COLUMN_NAME='auth_epoch') THEN
        ALTER TABLE api_keys DROP COLUMN auth_epoch;
    END IF;
END;
CALL hpg_mig139_down();
DROP PROCEDURE IF EXISTS hpg_mig139_down;
-- +goose StatementEnd
