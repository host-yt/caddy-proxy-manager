-- +goose Up
-- Existing active SSL routes never got ssl_issued_at populated.
-- Backfill with updated_at as best-effort proxy for last activation time.
UPDATE routes
   SET ssl_issued_at = COALESCE(updated_at, NOW())
 WHERE ssl_enabled = 1
   AND status = 'active'
   AND ssl_issued_at IS NULL;

-- +goose Down
-- No-op: refusing to wipe timestamps on rollback.
SELECT 1;
