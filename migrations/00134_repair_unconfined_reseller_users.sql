-- +goose Up
-- +goose StatementBegin
-- Repair rows the old assign path could leave behind: it committed reseller_id
-- first and ignored the separate role update, so a failure produced a
-- reseller-bound user with an unrestricted platform role. Deleting that
-- reseller would then hand them platform-wide access.
UPDATE users SET is_restricted = 1
 WHERE reseller_id IS NOT NULL
   AND role IN ('admin', 'support')
   AND COALESCE(is_restricted, 0) = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- No down: re-widening these accounts would reintroduce the escalation.
SELECT 1;
-- +goose StatementEnd
