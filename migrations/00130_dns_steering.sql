-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig130_up;
CREATE PROCEDURE hpg_mig130_up()
BEGIN
    -- Health-driven DNS steering: per-route toggle + provider selection.
    -- dns_provider_id is BIGINT UNSIGNED to match dns_providers.id PK - a
    -- signed FK fails at runtime with MySQL 3780 and crash-loops the app.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_steering_enabled') THEN
        ALTER TABLE routes ADD COLUMN dns_steering_enabled TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_provider_id') THEN
        ALTER TABLE routes ADD COLUMN dns_provider_id BIGINT UNSIGNED NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_steering_ttl') THEN
        ALTER TABLE routes ADD COLUMN dns_steering_ttl INT NOT NULL DEFAULT 60;
    END IF;
    -- ON DELETE SET NULL so deleting a provider disables steering on its
    -- routes (reconciler skips a NULL dns_provider_id) instead of orphaning a FK.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_routes_dns_provider') THEN
        ALTER TABLE routes
            ADD CONSTRAINT fk_routes_dns_provider FOREIGN KEY (dns_provider_id)
            REFERENCES dns_providers(id) ON DELETE SET NULL;
    END IF;

    -- Per (route, node) record bookkeeping so the reconciler can diff without
    -- re-listing the provider zone every tick and can fail-static (never
    -- remove the last present record even if its node is unhealthy - a stale
    -- A record beats NXDOMAIN for every client mid-flight).
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_steering_state') THEN
        CREATE TABLE dns_steering_state (
          route_id       BIGINT UNSIGNED NOT NULL,
          node_id        BIGINT UNSIGNED NOT NULL,
          record_value   VARCHAR(45) NOT NULL,
          present        TINYINT(1) NOT NULL DEFAULT 0,
          last_synced_at TIMESTAMP NULL,
          last_error     TEXT NULL,
          PRIMARY KEY (route_id, node_id),
          KEY idx_dss_node (node_id),
          CONSTRAINT fk_dss_route FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
          CONSTRAINT fk_dss_node FOREIGN KEY (node_id) REFERENCES caddy_nodes(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig130_up();
DROP PROCEDURE IF EXISTS hpg_mig130_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig130_down;
CREATE PROCEDURE hpg_mig130_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_steering_state') THEN
        DROP TABLE dns_steering_state;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_routes_dns_provider') THEN
        ALTER TABLE routes DROP FOREIGN KEY fk_routes_dns_provider;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_steering_ttl') THEN
        ALTER TABLE routes DROP COLUMN dns_steering_ttl;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_provider_id') THEN
        ALTER TABLE routes DROP COLUMN dns_provider_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_steering_enabled') THEN
        ALTER TABLE routes DROP COLUMN dns_steering_enabled;
    END IF;
END;
CALL hpg_mig130_down();
DROP PROCEDURE IF EXISTS hpg_mig130_down;
-- +goose StatementEnd
