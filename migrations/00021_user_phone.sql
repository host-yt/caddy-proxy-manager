-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig21_up;
CREATE PROCEDURE hpg_mig21_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='phone_e164') THEN
        ALTER TABLE users ADD COLUMN phone_e164 VARCHAR(16) NULL AFTER email;
    END IF;
END;
CALL hpg_mig21_up();
DROP PROCEDURE hpg_mig21_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig21_down;
CREATE PROCEDURE hpg_mig21_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='phone_e164') THEN
        ALTER TABLE users DROP COLUMN phone_e164;
    END IF;
END;
CALL hpg_mig21_down();
DROP PROCEDURE hpg_mig21_down;
-- +goose StatementEnd
