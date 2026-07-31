-- +goose Up
-- +goose StatementBegin
-- Stream destinations stored before target screening existed were re-emitted
-- verbatim by every resync. These columns park such a row so the push path
-- skips it and an operator can see why.
DROP PROCEDURE IF EXISTS hpg_mig137_up;
CREATE PROCEDURE hpg_mig137_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='stream_routes' AND COLUMN_NAME='quarantined_at') THEN
        ALTER TABLE stream_routes ADD COLUMN quarantined_at TIMESTAMP NULL;
        ALTER TABLE stream_routes ADD COLUMN quarantine_reason VARCHAR(255) NULL;
        -- Audit what SQL can decide on its own: the admin-API port and any
        -- destination equal to a node/control-plane address. Hostname targets
        -- and per-upstream host matching are screened at emission time.
        UPDATE stream_routes SET quarantined_at = NOW(),
               quarantine_reason = 'migration 00137: upstream port 2019 is the node admin API'
         WHERE quarantined_at IS NULL AND upstream_port = 2019;
        UPDATE stream_routes SET quarantined_at = NOW(),
               quarantine_reason = 'migration 00137: upstream address on the node admin API port'
         WHERE quarantined_at IS NULL
           AND id IN (SELECT stream_route_id FROM stream_upstreams WHERE address LIKE '%:2019');
        UPDATE stream_routes SET quarantined_at = NOW(),
               quarantine_reason = 'migration 00137: backend is a managed node address'
         WHERE quarantined_at IS NULL
           AND service_id IN (
                SELECT s.id FROM services s
                 WHERE s.backend_ip IN (SELECT public_ip FROM caddy_nodes WHERE public_ip IS NOT NULL)
                    OR s.backend_ip IN (SELECT wg_ip FROM caddy_nodes WHERE wg_ip IS NOT NULL));
    END IF;
END;
CALL hpg_mig137_up();
DROP PROCEDURE IF EXISTS hpg_mig137_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig137_down;
CREATE PROCEDURE hpg_mig137_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='stream_routes' AND COLUMN_NAME='quarantined_at') THEN
        ALTER TABLE stream_routes DROP COLUMN quarantined_at;
        ALTER TABLE stream_routes DROP COLUMN quarantine_reason;
    END IF;
END;
CALL hpg_mig137_down();
DROP PROCEDURE IF EXISTS hpg_mig137_down;
-- +goose StatementEnd
