-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig97_up;
CREATE PROCEDURE hpg_mig97_up()
BEGIN
    -- Add capability columns to caddy_nodes for module availability tracking.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='has_waf') THEN
        ALTER TABLE caddy_nodes
            ADD COLUMN has_waf           TINYINT(1)   NOT NULL DEFAULT 0    AFTER notes,
            ADD COLUMN has_l4            TINYINT(1)   NOT NULL DEFAULT 0    AFTER has_waf,
            ADD COLUMN has_dns_module    TINYINT(1)   NOT NULL DEFAULT 0    AFTER has_l4,
            ADD COLUMN has_rate_limit    TINYINT(1)   NOT NULL DEFAULT 0    AFTER has_dns_module,
            ADD COLUMN has_geoip         TINYINT(1)   NOT NULL DEFAULT 0    AFTER has_rate_limit,
            ADD COLUMN caddy_version     VARCHAR(32)  NULL                  AFTER has_geoip,
            ADD COLUMN modules_probed_at TIMESTAMP    NULL                  AFTER caddy_version;
    END IF;
END;
CALL hpg_mig97_up();
DROP PROCEDURE IF EXISTS hpg_mig97_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig97_down;
CREATE PROCEDURE hpg_mig97_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='has_waf') THEN
        ALTER TABLE caddy_nodes
            DROP COLUMN modules_probed_at,
            DROP COLUMN caddy_version,
            DROP COLUMN has_geoip,
            DROP COLUMN has_rate_limit,
            DROP COLUMN has_dns_module,
            DROP COLUMN has_l4,
            DROP COLUMN has_waf;
    END IF;
END;
CALL hpg_mig97_down();
DROP PROCEDURE IF EXISTS hpg_mig97_down;
-- +goose StatementEnd
