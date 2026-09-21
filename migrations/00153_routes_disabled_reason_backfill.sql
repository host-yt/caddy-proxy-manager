-- +goose Up
-- +goose StatementBegin
-- Grandfather the routes the old suspend path disabled: under a service that is
-- still suspended, a disabled route is one the suspend turned off, so resume
-- keeps restoring it. Routes under any other service status stay NULL (manual)
-- and resume will never touch them.
UPDATE routes
   SET disabled_reason = 'service_suspended'
 WHERE status = 'disabled'
   AND disabled_reason IS NULL
   AND service_id IN (SELECT id FROM services WHERE status = 'suspended');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Data backfill; the previous per-row values are not recoverable.
SELECT 1;
-- +goose StatementEnd
