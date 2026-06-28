-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig110_up;
CREATE PROCEDURE hpg_mig110_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='custom_field_defs') THEN
        CREATE TABLE custom_field_defs (
            id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
            entity_type VARCHAR(16)  NOT NULL,
            field_key   VARCHAR(40)  NOT NULL,
            label       VARCHAR(120) NOT NULL,
            field_type  VARCHAR(16)  NOT NULL,
            options_json TEXT        NULL,
            required    TINYINT(1)   NOT NULL DEFAULT 0,
            sort_order  INT          NOT NULL DEFAULT 0,
            created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_cf (entity_type, field_key)
        );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='custom_fields') THEN
        ALTER TABLE clients ADD COLUMN custom_fields JSON NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='custom_fields') THEN
        ALTER TABLE routes ADD COLUMN custom_fields JSON NULL;
    END IF;
END;
CALL hpg_mig110_up();
DROP PROCEDURE IF EXISTS hpg_mig110_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig110_down;
CREATE PROCEDURE hpg_mig110_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='custom_fields') THEN
        ALTER TABLE routes DROP COLUMN custom_fields;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='custom_fields') THEN
        ALTER TABLE clients DROP COLUMN custom_fields;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='custom_field_defs') THEN
        DROP TABLE custom_field_defs;
    END IF;
END;
CALL hpg_mig110_down();
DROP PROCEDURE IF EXISTS hpg_mig110_down;
-- +goose StatementEnd
