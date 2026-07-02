-- +goose Up
-- +goose StatementBegin
-- Explicit restriction flag for admins. Previously "restricted" was INFERRED
-- from the presence of admin_client_scope rows (0 rows = unrestricted). That is
-- a footgun: removing a scoped admin's LAST assigned client silently escalated
-- them to full platform access. This flag makes restriction explicit and
-- decouples it from the row count - a restricted admin with 0 assignments now
-- correctly sees nothing instead of everything. reseller_id still takes
-- precedence (reseller-admins are scoped by ownership regardless of this flag).
ALTER TABLE users ADD COLUMN is_restricted BOOLEAN NOT NULL DEFAULT 0;
-- +goose StatementEnd
-- +goose StatementBegin
-- Backfill: every admin that currently has scope rows is marked restricted so
-- behaviour is preserved and the footgun is closed for existing data.
UPDATE users SET is_restricted = 1
  WHERE id IN (SELECT admin_user_id FROM admin_client_scope);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN is_restricted;
-- +goose StatementEnd
