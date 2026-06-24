-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig49_up;
CREATE PROCEDURE hpg_mig49_up()
BEGIN
    -- Migration 48 added prev_rx_bytes/prev_tx_bytes DEFAULT 0 with no backfill.
    -- For a peer that already had traffic, the first stats report would compute
    -- delta = (full lifetime counter) - 0 and inflate cumulative_* once. Seed
    -- prev_* from the last raw snapshot (rx_bytes/tx_bytes) so the next report's
    -- delta is correct. No-op for fresh peers (rx/tx still 0) and idempotent
    -- (re-run skips rows whose prev_* is already non-zero).
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
        AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='prev_rx_bytes') THEN
        UPDATE customer_wg_peer
           SET prev_rx_bytes = rx_bytes, prev_tx_bytes = tx_bytes
         WHERE prev_rx_bytes = 0 AND prev_tx_bytes = 0
           AND (rx_bytes > 0 OR tx_bytes > 0);
    END IF;
END;
CALL hpg_mig49_up();
DROP PROCEDURE hpg_mig49_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- One-shot data correction; nothing to roll back.
SELECT 1;
-- +goose StatementEnd
