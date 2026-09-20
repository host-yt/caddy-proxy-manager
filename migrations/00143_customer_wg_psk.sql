-- +goose Up
-- +goose StatementBegin
-- Post-quantum hardening of the customer WireGuard tunnel: an optional
-- per-peer preshared key mixed into the WG handshake, so a recorded session
-- cannot be decrypted later by an attacker who breaks X25519.
--
-- psk_enc is envelope-encrypted with purpose "wg" (NULL = classic peer).
-- agent_psk records whether that node's node-agent reported psk_supported:
-- an old agent handed a PresharedKey line would have `wg syncconf` reject the
-- WHOLE config, so both peer creation and the peer pull gate on it. Default 0
-- means nothing changes for an existing fleet until the agents are upgraded.
DROP PROCEDURE IF EXISTS hpg_mig143_up;
CREATE PROCEDURE hpg_mig143_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='psk_enc') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN psk_enc TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='agent_psk') THEN
        ALTER TABLE caddy_nodes ADD COLUMN agent_psk TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig143_up();
DROP PROCEDURE IF EXISTS hpg_mig143_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig143_down;
CREATE PROCEDURE hpg_mig143_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='agent_psk') THEN
        ALTER TABLE caddy_nodes DROP COLUMN agent_psk;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='psk_enc') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN psk_enc;
    END IF;
END;
CALL hpg_mig143_down();
DROP PROCEDURE IF EXISTS hpg_mig143_down;
-- +goose StatementEnd
