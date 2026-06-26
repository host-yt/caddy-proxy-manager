-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig76_up;
CREATE PROCEDURE hpg_mig76_up()
BEGIN
    -- max_requests: Caddy upstream-level concurrency cap (0 = unlimited).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='max_requests') THEN
        ALTER TABLE route_upstreams ADD COLUMN max_requests INT NOT NULL DEFAULT 0 AFTER weight;
    END IF;
    -- enabled: soft-disable one upstream without deleting it from the pool.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='enabled') THEN
        ALTER TABLE route_upstreams ADD COLUMN enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER max_requests;
    END IF;
END;
CALL hpg_mig76_up();
DROP PROCEDURE IF EXISTS hpg_mig76_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig76_down;
CREATE PROCEDURE hpg_mig76_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='enabled') THEN
        ALTER TABLE route_upstreams DROP COLUMN enabled;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_upstreams' AND COLUMN_NAME='max_requests') THEN
        ALTER TABLE route_upstreams DROP COLUMN max_requests;
    END IF;
END;
CALL hpg_mig76_down();
DROP PROCEDURE IF EXISTS hpg_mig76_down;
-- +goose StatementEnd
