-- +goose Up
-- +goose StatementBegin
-- Mesh WireGuard preshared keys (PQ-01).
--
-- The panel<->node mesh carries Caddy config pushes, including manual-cert
-- private keys, so a recorded X25519 handshake is worth breaking later
-- (harvest-now-decrypt-later). A WG preshared key mixes 32 symmetric bytes
-- into every handshake, which no quantum adversary gets from the recording.
--
-- wg_psk_enc is the ACTIVE key rendered into wg0.conf. wg_psk_pending_enc is
-- staged by enable/rotate and only becomes active once the node confirms it
-- installed the key - until then the old key keeps the mesh alive. The token
-- columns authenticate that one confirmation (single node, 30 min TTL).
DROP PROCEDURE IF EXISTS hpg_mig142_up;
CREATE PROCEDURE hpg_mig142_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_enc') THEN
        ALTER TABLE caddy_nodes ADD COLUMN wg_psk_enc TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_pending_enc') THEN
        ALTER TABLE caddy_nodes ADD COLUMN wg_psk_pending_enc TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_token_hash') THEN
        ALTER TABLE caddy_nodes ADD COLUMN wg_psk_token_hash CHAR(64) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_token_enc') THEN
        ALTER TABLE caddy_nodes ADD COLUMN wg_psk_token_enc TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_token_expires') THEN
        ALTER TABLE caddy_nodes ADD COLUMN wg_psk_token_expires TIMESTAMP NULL;
    END IF;
    -- The unauthenticated rekey endpoints look nodes up by this hash and the
    -- confirm does it FOR UPDATE; unindexed that is a full scan plus next-key
    -- locks across caddy_nodes on every request, authenticated or not.
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND INDEX_NAME='idx_node_wg_psk_token') THEN
        ALTER TABLE caddy_nodes ADD KEY idx_node_wg_psk_token (wg_psk_token_hash);
    END IF;
END;
CALL hpg_mig142_up();
DROP PROCEDURE IF EXISTS hpg_mig142_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig142_down;
CREATE PROCEDURE hpg_mig142_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND INDEX_NAME='idx_node_wg_psk_token') THEN
        ALTER TABLE caddy_nodes DROP KEY idx_node_wg_psk_token;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_token_expires') THEN
        ALTER TABLE caddy_nodes DROP COLUMN wg_psk_token_expires;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_token_enc') THEN
        ALTER TABLE caddy_nodes DROP COLUMN wg_psk_token_enc;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_token_hash') THEN
        ALTER TABLE caddy_nodes DROP COLUMN wg_psk_token_hash;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_pending_enc') THEN
        ALTER TABLE caddy_nodes DROP COLUMN wg_psk_pending_enc;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='wg_psk_enc') THEN
        ALTER TABLE caddy_nodes DROP COLUMN wg_psk_enc;
    END IF;
END;
CALL hpg_mig142_down();
DROP PROCEDURE IF EXISTS hpg_mig142_down;
-- +goose StatementEnd
