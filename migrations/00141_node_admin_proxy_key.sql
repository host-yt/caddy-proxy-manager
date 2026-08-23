-- +goose Up
-- +goose StatementBegin
-- Per-node key the panel presents to that node's node-agent admin proxy.
--
-- Caddy's admin API has no authentication of its own, so a node that publishes
-- it on its WireGuard address treats "can reach the port" as authorization. A
-- node whose agent fronts the API instead gets a key here (encrypted at rest);
-- the panel sends it as a bearer token and the agent refuses anything else.
--
-- NULL = this node is still reached directly, exactly as before. Nothing
-- changes for an existing fleet until the operator migrates a node.
DROP PROCEDURE IF EXISTS hpg_mig141_up;
CREATE PROCEDURE hpg_mig141_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='admin_proxy_key_enc') THEN
        ALTER TABLE caddy_nodes ADD COLUMN admin_proxy_key_enc TEXT NULL;
    END IF;
END;
CALL hpg_mig141_up();
DROP PROCEDURE IF EXISTS hpg_mig141_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig141_down;
CREATE PROCEDURE hpg_mig141_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='admin_proxy_key_enc') THEN
        ALTER TABLE caddy_nodes DROP COLUMN admin_proxy_key_enc;
    END IF;
END;
CALL hpg_mig141_down();
DROP PROCEDURE IF EXISTS hpg_mig141_down;
-- +goose StatementEnd
