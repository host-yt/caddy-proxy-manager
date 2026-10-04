-- +goose Up
-- +goose StatementBegin
-- Per-node GeoIP DB presence reported by hpg-node-agent (OPS-005). NULL = never
-- reported (old agent / no agent): emission falls back to the panel's own copy.
DROP PROCEDURE IF EXISTS hpg_mig162_up;
CREATE PROCEDURE hpg_mig162_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='geoip_db_present') THEN
        ALTER TABLE caddy_nodes ADD COLUMN geoip_db_present TINYINT(1) NULL;
    END IF;
END;
CALL hpg_mig162_up();
DROP PROCEDURE IF EXISTS hpg_mig162_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig162_down;
CREATE PROCEDURE hpg_mig162_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='geoip_db_present') THEN
        ALTER TABLE caddy_nodes DROP COLUMN geoip_db_present;
    END IF;
END;
CALL hpg_mig162_down();
DROP PROCEDURE IF EXISTS hpg_mig162_down;
-- +goose StatementEnd
