-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig107_up;
CREATE PROCEDURE hpg_mig107_up()
BEGIN
    -- Global ts index for WAF analytics queries (wafSummary, get_waf_events AI tool)
    -- that filter by time window without a route_id prefix. The existing
    -- idx_waf_route_ts covers per-route queries; this covers global ones.
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_events' AND INDEX_NAME='idx_waf_ts') THEN
        ALTER TABLE waf_events ADD KEY idx_waf_ts (ts);
    END IF;
END;
CALL hpg_mig107_up();
DROP PROCEDURE IF EXISTS hpg_mig107_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig107_down;
CREATE PROCEDURE hpg_mig107_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='waf_events' AND INDEX_NAME='idx_waf_ts') THEN
        ALTER TABLE waf_events DROP KEY idx_waf_ts;
    END IF;
END;
CALL hpg_mig107_down();
DROP PROCEDURE IF EXISTS hpg_mig107_down;
-- +goose StatementEnd
