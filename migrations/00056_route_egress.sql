-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig56_up;
CREATE PROCEDURE hpg_mig56_up()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'caddy_nodes'
          AND COLUMN_NAME = 'outbound_ips'
    ) THEN
        ALTER TABLE caddy_nodes ADD COLUMN outbound_ips JSON NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'routes'
          AND COLUMN_NAME = 'outbound_ip_mode'
    ) THEN
        ALTER TABLE routes ADD COLUMN outbound_ip_mode ENUM('default','fixed') NOT NULL DEFAULT 'default';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'routes'
          AND COLUMN_NAME = 'outbound_ip'
    ) THEN
        ALTER TABLE routes ADD COLUMN outbound_ip VARCHAR(45) NULL;
    END IF;
END;
CALL hpg_mig56_up();
DROP PROCEDURE hpg_mig56_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig56_down;
CREATE PROCEDURE hpg_mig56_down()
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'routes'
          AND COLUMN_NAME = 'outbound_ip'
    ) THEN
        ALTER TABLE routes DROP COLUMN outbound_ip;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'routes'
          AND COLUMN_NAME = 'outbound_ip_mode'
    ) THEN
        ALTER TABLE routes DROP COLUMN outbound_ip_mode;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'caddy_nodes'
          AND COLUMN_NAME = 'outbound_ips'
    ) THEN
        ALTER TABLE caddy_nodes DROP COLUMN outbound_ips;
    END IF;
END;
CALL hpg_mig56_down();
DROP PROCEDURE hpg_mig56_down;
-- +goose StatementEnd
