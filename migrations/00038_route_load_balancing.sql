-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig38_up;
CREATE PROCEDURE hpg_mig38_up()
BEGIN
    -- Additional backends for a route. The primary backend stays in
    -- routes.upstream_port + resolved host; an empty set = single-backend route.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams') THEN
        CREATE TABLE route_upstreams (
            id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            route_id    BIGINT UNSIGNED NOT NULL,
            host        VARCHAR(255) NOT NULL,
            port        INT NOT NULL,
            weight      INT NOT NULL DEFAULT 1,
            sort_order  INT NOT NULL DEFAULT 0,
            created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_route_upstreams_route FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
            INDEX idx_route_upstreams_route (route_id, sort_order)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
    -- LB policy: '' (Caddy default) | round_robin | least_conn | ip_hash | weighted_round_robin.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_policy') THEN
        ALTER TABLE routes ADD COLUMN lb_policy VARCHAR(32) NOT NULL DEFAULT '' AFTER upstream_scheme;
    END IF;
    -- Active health check (empty health_active_uri = active disabled).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='health_active_uri') THEN
        ALTER TABLE routes ADD COLUMN health_active_uri      VARCHAR(255) NOT NULL DEFAULT '' AFTER lb_policy;
        ALTER TABLE routes ADD COLUMN health_active_interval INT NOT NULL DEFAULT 10 AFTER health_active_uri;
        ALTER TABLE routes ADD COLUMN health_active_timeout  INT NOT NULL DEFAULT 5  AFTER health_active_interval;
        ALTER TABLE routes ADD COLUMN health_active_status   INT NOT NULL DEFAULT 0  AFTER health_active_timeout;
        ALTER TABLE routes ADD COLUMN health_active_fails    INT NOT NULL DEFAULT 3  AFTER health_active_status;
    END IF;
    -- Passive health check (health_passive_enabled=0 = passive omitted).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='health_passive_enabled') THEN
        ALTER TABLE routes ADD COLUMN health_passive_enabled  TINYINT(1) NOT NULL DEFAULT 0 AFTER health_active_fails;
        ALTER TABLE routes ADD COLUMN health_passive_fail_dur INT NOT NULL DEFAULT 30 AFTER health_passive_enabled;
        ALTER TABLE routes ADD COLUMN health_passive_max_fail INT NOT NULL DEFAULT 3  AFTER health_passive_fail_dur;
    END IF;
END;
CALL hpg_mig38_up();
DROP PROCEDURE hpg_mig38_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig38_down;
CREATE PROCEDURE hpg_mig38_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='health_passive_enabled') THEN
        ALTER TABLE routes DROP COLUMN health_passive_max_fail;
        ALTER TABLE routes DROP COLUMN health_passive_fail_dur;
        ALTER TABLE routes DROP COLUMN health_passive_enabled;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='health_active_uri') THEN
        ALTER TABLE routes DROP COLUMN health_active_fails;
        ALTER TABLE routes DROP COLUMN health_active_status;
        ALTER TABLE routes DROP COLUMN health_active_timeout;
        ALTER TABLE routes DROP COLUMN health_active_interval;
        ALTER TABLE routes DROP COLUMN health_active_uri;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='lb_policy') THEN
        ALTER TABLE routes DROP COLUMN lb_policy;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams') THEN
        DROP TABLE route_upstreams;
    END IF;
END;
CALL hpg_mig38_down();
DROP PROCEDURE hpg_mig38_down;
-- +goose StatementEnd
