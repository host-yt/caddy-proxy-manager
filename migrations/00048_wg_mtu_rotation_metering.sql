-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig48_up;
CREATE PROCEDURE hpg_mig48_up()
BEGIN
    -- WG key-rotation schedule (0 = disabled) + per-peer rotation bookkeeping.
    IF NOT EXISTS (SELECT 1 FROM settings WHERE `key` = 'wg.key_rotation_days') THEN
        INSERT INTO settings (`key`, `value`) VALUES ('wg.key_rotation_days', '0');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='last_key_rotation_at') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN last_key_rotation_at TIMESTAMP NULL;
    END IF;
    -- Auto-MTU probe result per node (1420 = safe default / probe failed).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_mtu') THEN
        ALTER TABLE caddy_nodes ADD COLUMN tunnel_mtu INT UNSIGNED NOT NULL DEFAULT 1420;
    END IF;
    -- Bandwidth metering: cumulative counters survive wg counter resets
    -- (rekey/restart) by adding deltas; prev_* is the last raw snapshot.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='cumulative_rx_bytes') THEN
        ALTER TABLE customer_wg_peer
            ADD COLUMN cumulative_rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            ADD COLUMN cumulative_tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            ADD COLUMN prev_rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
            ADD COLUMN prev_tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0;
    END IF;
    -- Periodic usage samples for history / billing graphs.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer_usage_sample') THEN
        CREATE TABLE customer_wg_peer_usage_sample (
            id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
            peer_id BIGINT UNSIGNED NOT NULL,
            node_id BIGINT UNSIGNED NOT NULL,
            sampled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            rx_delta BIGINT UNSIGNED NOT NULL DEFAULT 0,
            tx_delta BIGINT UNSIGNED NOT NULL DEFAULT 0,
            INDEX idx_peer_sampled (peer_id, sampled_at),
            FOREIGN KEY (peer_id) REFERENCES customer_wg_peer(id) ON DELETE CASCADE
        );
    END IF;
END;
CALL hpg_mig48_up();
DROP PROCEDURE hpg_mig48_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig48_down;
CREATE PROCEDURE hpg_mig48_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer_usage_sample') THEN
        DROP TABLE customer_wg_peer_usage_sample;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='cumulative_rx_bytes') THEN
        ALTER TABLE customer_wg_peer
            DROP COLUMN cumulative_rx_bytes, DROP COLUMN cumulative_tx_bytes,
            DROP COLUMN prev_rx_bytes, DROP COLUMN prev_tx_bytes;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='tunnel_mtu') THEN
        ALTER TABLE caddy_nodes DROP COLUMN tunnel_mtu;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='last_key_rotation_at') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN last_key_rotation_at;
    END IF;
    DELETE FROM settings WHERE `key` = 'wg.key_rotation_days';
END;
CALL hpg_mig48_down();
DROP PROCEDURE hpg_mig48_down;
-- +goose StatementEnd
