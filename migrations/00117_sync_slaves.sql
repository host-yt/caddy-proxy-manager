-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig117_up;
CREATE PROCEDURE hpg_mig117_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sync_slaves') THEN
        CREATE TABLE sync_slaves (
            id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
            name             VARCHAR(255) NOT NULL,
            url              VARCHAR(2000) NOT NULL,
            token_enc        TEXT NOT NULL,
            last_sync_at     DATETIME NULL,
            last_sync_status VARCHAR(10) NULL DEFAULT NULL,
            last_sync_error  TEXT NULL,
            created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig117_up();
DROP PROCEDURE IF EXISTS hpg_mig117_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sync_slaves;
-- +goose StatementEnd
