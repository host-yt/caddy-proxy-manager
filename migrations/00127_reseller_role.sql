-- +goose Up
-- +goose StatementBegin
-- F2: promote existing reseller-admins to the explicit reseller role. Ships in
-- the same release as the guard rewrite that accepts role='reseller', so no
-- lockout window. Enum value was added in 00126.
UPDATE users SET role = 'reseller' WHERE role = 'admin' AND reseller_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE users SET role = 'admin' WHERE role = 'reseller';
-- +goose StatementEnd
