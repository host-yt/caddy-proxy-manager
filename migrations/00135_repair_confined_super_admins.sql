-- +goose Up
-- +goose StatementBegin
-- Promotion to super_admin used to update only the role, so is_restricted /
-- reseller_id / admin_client_scope rows survived and kept confining the account
-- after the forced relogin - unrecoverable, the scope editor skips super_admins.
UPDATE users SET is_restricted = 0, reseller_id = NULL
 WHERE role = 'super_admin'
   AND (COALESCE(is_restricted, 0) <> 0 OR reseller_id IS NOT NULL);
-- +goose StatementEnd

-- +goose StatementBegin
DELETE FROM admin_client_scope
 WHERE admin_user_id IN (SELECT id FROM users WHERE role = 'super_admin');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- No down: re-confining a super_admin would lock the platform owner out.
SELECT 1;
-- +goose StatementEnd
