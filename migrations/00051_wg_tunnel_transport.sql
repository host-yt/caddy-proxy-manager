-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig51_up;
CREATE PROCEDURE hpg_mig51_up()
BEGIN
    -- Transport mode for WSS-over-TLS tunnelling (wstunnel); default 'udp' = unchanged behaviour.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_transport') THEN
        ALTER TABLE caddy_nodes
            ADD COLUMN tunnel_transport     ENUM('udp','wss','auto') NOT NULL DEFAULT 'udp',
            ADD COLUMN tunnel_wstunnel_port SMALLINT UNSIGNED NULL,
            -- node-reported wstunnel capability: panel gates WSS route/installer on this
            -- being healthy+fresh, so it never advertises WSS a node can't actually serve.
            ADD COLUMN tunnel_wstunnel_healthy     TINYINT(1) NULL,
            ADD COLUMN tunnel_wstunnel_reported_at DATETIME   NULL,
            -- forced wss is broken without a backend port; refuse that state at write time.
            ADD CONSTRAINT chk_wstunnel_port CHECK (tunnel_transport <> 'wss' OR tunnel_wstunnel_port IS NOT NULL);
    END IF;
END;
CALL hpg_mig51_up();
DROP PROCEDURE hpg_mig51_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig51_down;
CREATE PROCEDURE hpg_mig51_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_transport') THEN
        ALTER TABLE caddy_nodes DROP CONSTRAINT IF EXISTS chk_wstunnel_port;
        ALTER TABLE caddy_nodes
            DROP COLUMN tunnel_transport,
            DROP COLUMN tunnel_wstunnel_port,
            DROP COLUMN tunnel_wstunnel_healthy,
            DROP COLUMN tunnel_wstunnel_reported_at;
    END IF;
END;
CALL hpg_mig51_down();
DROP PROCEDURE hpg_mig51_down;
-- +goose StatementEnd
