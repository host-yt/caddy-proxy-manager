-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig109_up;
CREATE PROCEDURE hpg_mig109_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='tag') THEN
        ALTER TABLE clients ADD COLUMN tag VARCHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='category') THEN
        ALTER TABLE clients ADD COLUMN category VARCHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND INDEX_NAME='idx_client_tag') THEN
        CREATE INDEX idx_client_tag ON clients (tag);
    END IF;
END;
CALL hpg_mig109_up();
DROP PROCEDURE IF EXISTS hpg_mig109_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig109_down;
CREATE PROCEDURE hpg_mig109_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND INDEX_NAME='idx_client_tag') THEN
        ALTER TABLE clients DROP INDEX idx_client_tag;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='category') THEN
        ALTER TABLE clients DROP COLUMN category;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='tag') THEN
        ALTER TABLE clients DROP COLUMN tag;
    END IF;
END;
CALL hpg_mig109_down();
DROP PROCEDURE IF EXISTS hpg_mig109_down;
-- +goose StatementEnd
