-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig66_up;
CREATE PROCEDURE hpg_mig66_up()
BEGIN
    -- Suppress table for WAF rules (global or per-route, with optional expiry).
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_rule_suppressions') THEN
        CREATE TABLE waf_rule_suppressions (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            rule_id    VARCHAR(128)    NOT NULL,
            route_id   BIGINT UNSIGNED NULL,          -- NULL = global; non-null = scoped to one route
            reason     VARCHAR(255)    NOT NULL DEFAULT '',
            created_by BIGINT UNSIGNED NOT NULL,
            created_at TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME        NULL,          -- NULL = permanent
            PRIMARY KEY (id),
            INDEX idx_wrs_rule_route (rule_id, route_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    -- Per-event ack columns on waf_events.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_events'
                     AND COLUMN_NAME='acknowledged_at') THEN
        ALTER TABLE waf_events
            ADD COLUMN acknowledged_at DATETIME NULL,
            ADD COLUMN acknowledged_by BIGINT UNSIGNED NULL;
    END IF;
END;
CALL hpg_mig66_up();
DROP PROCEDURE hpg_mig66_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig66_down;
CREATE PROCEDURE hpg_mig66_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_rule_suppressions') THEN
        DROP TABLE waf_rule_suppressions;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_events'
                 AND COLUMN_NAME='acknowledged_at') THEN
        ALTER TABLE waf_events
            DROP COLUMN acknowledged_at,
            DROP COLUMN acknowledged_by;
    END IF;
END;
CALL hpg_mig66_down();
DROP PROCEDURE hpg_mig66_down;
-- +goose StatementEnd
