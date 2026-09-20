-- +goose Up
-- +goose StatementBegin
-- Per-host post-quantum-only TLS. Opt-in: the route's connection policy is
-- pinned to curves=[x25519mlkem768] + protocol_min=tls1.3, so a client that
-- cannot do hybrid ML-KEM fails the handshake instead of silently falling
-- back to classical X25519. 0 = today's behaviour (hybrid offered, classical
-- still accepted), which stays the default for every existing route.
DROP PROCEDURE IF EXISTS hpg_mig144_up;
CREATE PROCEDURE hpg_mig144_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='tls_pq_only') THEN
        ALTER TABLE routes ADD COLUMN tls_pq_only TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig144_up();
DROP PROCEDURE IF EXISTS hpg_mig144_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig144_down;
CREATE PROCEDURE hpg_mig144_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='tls_pq_only') THEN
        ALTER TABLE routes DROP COLUMN tls_pq_only;
    END IF;
END;
CALL hpg_mig144_down();
DROP PROCEDURE IF EXISTS hpg_mig144_down;
-- +goose StatementEnd
