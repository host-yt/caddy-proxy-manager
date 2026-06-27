-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig99_up;
CREATE PROCEDURE hpg_mig99_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='notes') THEN
        ALTER TABLE clients ADD COLUMN notes TEXT;
    END IF;
END;
CALL hpg_mig99_up();
DROP PROCEDURE hpg_mig99_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE clients DROP COLUMN IF EXISTS notes;
-- +goose StatementEnd
