-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig50_up;
CREATE PROCEDURE hpg_mig50_up()
BEGIN
    -- Node forwarding diagnostics reported by the node-agent stats POST.
    -- All NULLable: older agents that don't send the `node` block leave them
    -- NULL so the panel can show "unknown" instead of a false negative.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='fwd_ip_forward_enabled') THEN
        ALTER TABLE caddy_nodes
            ADD COLUMN fwd_ip_forward_enabled    TINYINT(1) NULL,
            ADD COLUMN fwd_policy_drop_detected   TINYINT(1) NULL,
            ADD COLUMN fwd_docker_rules_installed TINYINT(1) NULL,
            ADD COLUMN fwd_firewall_backend       VARCHAR(32) NULL,
            ADD COLUMN fwd_mtu                     INT UNSIGNED NULL,
            ADD COLUMN fwd_last_setup_error        VARCHAR(512) NULL,
            ADD COLUMN fwd_reported_at             TIMESTAMP NULL;
    END IF;
END;
CALL hpg_mig50_up();
DROP PROCEDURE hpg_mig50_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig50_down;
CREATE PROCEDURE hpg_mig50_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='fwd_ip_forward_enabled') THEN
        ALTER TABLE caddy_nodes
            DROP COLUMN fwd_ip_forward_enabled,
            DROP COLUMN fwd_policy_drop_detected,
            DROP COLUMN fwd_docker_rules_installed,
            DROP COLUMN fwd_firewall_backend,
            DROP COLUMN fwd_mtu,
            DROP COLUMN fwd_last_setup_error,
            DROP COLUMN fwd_reported_at;
    END IF;
END;
CALL hpg_mig50_down();
DROP PROCEDURE hpg_mig50_down;
-- +goose StatementEnd
