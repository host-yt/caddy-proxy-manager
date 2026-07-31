-- +goose Up
-- +goose StatementBegin
-- Per-user authorization epoch. Bumped on every credential-invalidating change
-- (role, scope, activation, password, delete) so a session or pending-2FA
-- ticket minted before the change stops validating even if the best-effort
-- Redis session purge fails.
DROP PROCEDURE IF EXISTS hpg_mig132_up;
CREATE PROCEDURE hpg_mig132_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='auth_epoch') THEN
        ALTER TABLE users ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig132_up();
DROP PROCEDURE IF EXISTS hpg_mig132_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig132_down;
CREATE PROCEDURE hpg_mig132_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='auth_epoch') THEN
        ALTER TABLE users DROP COLUMN auth_epoch;
    END IF;
END;
CALL hpg_mig132_down();
DROP PROCEDURE IF EXISTS hpg_mig132_down;
-- +goose StatementEnd
