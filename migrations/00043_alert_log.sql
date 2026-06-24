-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig43_up;
CREATE PROCEDURE hpg_mig43_up()
BEGIN
    -- alert_log: dedupe/cooldown store + admin audit trail for fired alerts.
    -- No FK to caddy_nodes/routes - rule_id + labels_json is self-describing
    -- and survives entity deletion without cascade headaches.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='alert_log') THEN
        CREATE TABLE alert_log (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            rule_id     VARCHAR(64)  NOT NULL,
            severity    ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
            title       VARCHAR(255) NOT NULL,
            detail      TEXT         NULL,
            labels_json JSON         NULL,
            dedupe_key  VARCHAR(512) NOT NULL,
            fired_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_alert_log_rule_fired (rule_id, fired_at),
            KEY idx_alert_log_dedupe    (dedupe_key, fired_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig43_up();
DROP PROCEDURE hpg_mig43_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig43_down;
CREATE PROCEDURE hpg_mig43_down()
BEGIN
    DROP TABLE IF EXISTS alert_log;
END;
CALL hpg_mig43_down();
DROP PROCEDURE hpg_mig43_down;
-- +goose StatementEnd
