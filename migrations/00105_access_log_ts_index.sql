-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig105_up;
CREATE PROCEDURE hpg_mig105_up()
BEGIN
    -- Global ts index for analytics queries that filter by time window without a
    -- route_id prefix (AI tools, admin stats, cross-route aggregations).
    -- The existing idx_hal_route_ts covers per-route queries; this covers global ones.
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log' AND INDEX_NAME='idx_hal_ts') THEN
        ALTER TABLE host_access_log ADD KEY idx_hal_ts (ts);
    END IF;
END;
CALL hpg_mig105_up();
DROP PROCEDURE IF EXISTS hpg_mig105_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig105_down;
CREATE PROCEDURE hpg_mig105_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log' AND INDEX_NAME='idx_hal_ts') THEN
        ALTER TABLE host_access_log DROP KEY idx_hal_ts;
    END IF;
END;
CALL hpg_mig105_down();
DROP PROCEDURE IF EXISTS hpg_mig105_down;
-- +goose StatementEnd
