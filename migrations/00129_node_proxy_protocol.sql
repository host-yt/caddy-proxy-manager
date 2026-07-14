-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig129_up;
CREATE PROCEDURE hpg_mig129_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='proxy_protocol_in') THEN
        ALTER TABLE caddy_nodes ADD COLUMN proxy_protocol_in TINYINT(1) NOT NULL DEFAULT 0 AFTER modules_probed_at;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='proxy_protocol_allow') THEN
        ALTER TABLE caddy_nodes ADD COLUMN proxy_protocol_allow VARCHAR(1024) NOT NULL DEFAULT '' AFTER proxy_protocol_in;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='proxy_protocol_timeout_ms') THEN
        ALTER TABLE caddy_nodes ADD COLUMN proxy_protocol_timeout_ms INT NOT NULL DEFAULT 5000 AFTER proxy_protocol_allow;
    END IF;
END;
CALL hpg_mig129_up();
DROP PROCEDURE IF EXISTS hpg_mig129_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig129_down;
CREATE PROCEDURE hpg_mig129_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='proxy_protocol_timeout_ms') THEN
        ALTER TABLE caddy_nodes DROP COLUMN proxy_protocol_timeout_ms;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='proxy_protocol_allow') THEN
        ALTER TABLE caddy_nodes DROP COLUMN proxy_protocol_allow;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='proxy_protocol_in') THEN
        ALTER TABLE caddy_nodes DROP COLUMN proxy_protocol_in;
    END IF;
END;
CALL hpg_mig129_down();
DROP PROCEDURE IF EXISTS hpg_mig129_down;
-- +goose StatementEnd
