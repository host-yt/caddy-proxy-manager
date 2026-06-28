-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig111_up;
CREATE PROCEDURE hpg_mig111_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_header_field') THEN
        ALTER TABLE routes ADD COLUMN lb_header_field VARCHAR(128) NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_cookie_name') THEN
        ALTER TABLE routes ADD COLUMN lb_cookie_name VARCHAR(128) NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_cookie_secret') THEN
        ALTER TABLE routes ADD COLUMN lb_cookie_secret VARCHAR(255) NOT NULL DEFAULT '';
    END IF;
END;
CALL hpg_mig111_up();
DROP PROCEDURE IF EXISTS hpg_mig111_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig111_down;
CREATE PROCEDURE hpg_mig111_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_cookie_secret') THEN
        ALTER TABLE routes DROP COLUMN lb_cookie_secret;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_cookie_name') THEN
        ALTER TABLE routes DROP COLUMN lb_cookie_name;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_header_field') THEN
        ALTER TABLE routes DROP COLUMN lb_header_field;
    END IF;
END;
CALL hpg_mig111_down();
DROP PROCEDURE IF EXISTS hpg_mig111_down;
-- +goose StatementEnd
