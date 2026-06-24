-- +goose Up
-- +goose StatementBegin

-- Idempotent via information_schema guards. ADD COLUMN IF NOT EXISTS
-- nie dziala na MySQL (i nie zawsze na MariaDB) → uzywamy procedury.

DROP PROCEDURE IF EXISTS hpg_mig20_up;
CREATE PROCEDURE hpg_mig20_up()
BEGIN
    -- caddy_nodes columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_enabled') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_enabled TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_listen_port') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_listen_port INT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_endpoint') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_endpoint VARCHAR(255) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_subnet') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_subnet VARCHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_pubkey') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_pubkey VARCHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_privkey_e2') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_privkey_e2 VARBINARY(512) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_next_octet') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_next_octet INT NOT NULL DEFAULT 2;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='agent_token_hash') THEN
        ALTER TABLE caddy_nodes ADD COLUMN agent_token_hash CHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND INDEX_NAME='idx_agent_token') THEN
        ALTER TABLE caddy_nodes ADD KEY idx_agent_token (agent_token_hash);
    END IF;

    -- customer_wg_peer table. Typy musza pasowac do clients.id + caddy_nodes.id
    -- ktore sa BIGINT UNSIGNED (init mig).
    CREATE TABLE IF NOT EXISTS customer_wg_peer (
        id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        client_id BIGINT UNSIGNED NOT NULL,
        node_id BIGINT UNSIGNED NOT NULL,
        name VARCHAR(64) NOT NULL,
        pubkey VARCHAR(64) NULL,
        server_privkey_e2 VARBINARY(512) NULL,
        assigned_ip VARCHAR(64) NOT NULL,
        status ENUM('pending','active','revoked') NOT NULL DEFAULT 'pending',
        last_handshake_at TIMESTAMP NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        activated_at TIMESTAMP NULL,
        revoked_at TIMESTAMP NULL,
        CONSTRAINT fk_wgpeer_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
        CONSTRAINT fk_wgpeer_node   FOREIGN KEY (node_id) REFERENCES caddy_nodes(id) ON DELETE CASCADE,
        UNIQUE KEY uq_node_ip (node_id, assigned_ip),
        UNIQUE KEY uq_node_pubkey (node_id, pubkey),
        KEY idx_client (client_id),
        KEY idx_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    -- customer_wg_bootstrap table
    CREATE TABLE IF NOT EXISTS customer_wg_bootstrap (
        token CHAR(64) PRIMARY KEY,
        peer_id BIGINT UNSIGNED NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        consumed_at TIMESTAMP NULL,
        expires_at TIMESTAMP NOT NULL,
        CONSTRAINT fk_wgboot_peer FOREIGN KEY (peer_id) REFERENCES customer_wg_peer(id) ON DELETE CASCADE,
        KEY idx_peer (peer_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

    -- routes.via_wg_peer_id column. UNSIGNED bo customer_wg_peer.id jest UNSIGNED.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='via_wg_peer_id') THEN
        ALTER TABLE routes ADD COLUMN via_wg_peer_id BIGINT UNSIGNED NULL AFTER upstream_skip_tls_verify;
    END IF;

    -- routes FK to customer_wg_peer
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_route_wgpeer') THEN
        ALTER TABLE routes ADD CONSTRAINT fk_route_wgpeer FOREIGN KEY (via_wg_peer_id) REFERENCES customer_wg_peer(id) ON DELETE SET NULL;
    END IF;
END;
CALL hpg_mig20_up();
DROP PROCEDURE hpg_mig20_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig20_down;
CREATE PROCEDURE hpg_mig20_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_route_wgpeer') THEN
        ALTER TABLE routes DROP FOREIGN KEY fk_route_wgpeer;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='via_wg_peer_id') THEN
        ALTER TABLE routes DROP COLUMN via_wg_peer_id;
    END IF;
END;
CALL hpg_mig20_down();
DROP PROCEDURE hpg_mig20_down;

DROP TABLE IF EXISTS customer_wg_bootstrap;
DROP TABLE IF EXISTS customer_wg_peer;

DROP PROCEDURE IF EXISTS hpg_mig20_nodes_down;
CREATE PROCEDURE hpg_mig20_nodes_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND INDEX_NAME='idx_agent_token') THEN
        ALTER TABLE caddy_nodes DROP KEY idx_agent_token;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='agent_token_hash') THEN
        ALTER TABLE caddy_nodes DROP COLUMN agent_token_hash;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_next_octet') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_next_octet;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_privkey_e2') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_privkey_e2;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_pubkey') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_pubkey;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_subnet') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_subnet;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_endpoint') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_endpoint;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_listen_port') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_listen_port;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_enabled') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_enabled;
    END IF;
END;
CALL hpg_mig20_nodes_down();
DROP PROCEDURE hpg_mig20_nodes_down;
-- +goose StatementEnd
