-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig53_up;
CREATE PROCEDURE hpg_mig53_up()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'routes'
          AND COLUMN_NAME = 'sso_strict_mode'
    ) THEN
        ALTER TABLE routes
            ADD COLUMN sso_strict_mode TINYINT(1) NOT NULL DEFAULT 0 AFTER sso_provider_url;
    END IF;
END;
CALL hpg_mig53_up();
DROP PROCEDURE hpg_mig53_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig53_down;
CREATE PROCEDURE hpg_mig53_down()
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'routes'
          AND COLUMN_NAME = 'sso_strict_mode'
    ) THEN
        ALTER TABLE routes DROP COLUMN sso_strict_mode;
    END IF;
END;
CALL hpg_mig53_down();
DROP PROCEDURE hpg_mig53_down;
-- +goose StatementEnd
