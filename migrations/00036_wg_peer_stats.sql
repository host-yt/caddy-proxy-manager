-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig36_up;
CREATE PROCEDURE hpg_mig36_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE()
                      AND TABLE_NAME='customer_wg_peer'
                      AND COLUMN_NAME='rx_bytes') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN rx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE()
                      AND TABLE_NAME='customer_wg_peer'
                      AND COLUMN_NAME='tx_bytes') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN tx_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0;
    END IF;
    -- endpoint observed by the node (may differ from caddy_nodes.tunnel_endpoint
    -- when the peer is behind NAT and the node sees the real source IP:port).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE()
                      AND TABLE_NAME='customer_wg_peer'
                      AND COLUMN_NAME='endpoint') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN endpoint VARCHAR(64) NULL;
    END IF;
    -- Raw WG epoch; panel derives staleness from this (panel time.Now() can
    -- diverge from the node kernel clock). last_handshake_at (migration 00020)
    -- stays and is now set via FROM_UNIXTIME(epoch).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE()
                      AND TABLE_NAME='customer_wg_peer'
                      AND COLUMN_NAME='last_handshake_epoch') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN last_handshake_epoch INT UNSIGNED NULL;
    END IF;
END;
CALL hpg_mig36_up();
DROP PROCEDURE hpg_mig36_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig36_down;
CREATE PROCEDURE hpg_mig36_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='last_handshake_epoch') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN last_handshake_epoch;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='endpoint') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN endpoint;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='tx_bytes') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN tx_bytes;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='rx_bytes') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN rx_bytes;
    END IF;
END;
CALL hpg_mig36_down();
DROP PROCEDURE hpg_mig36_down;
-- +goose StatementEnd
