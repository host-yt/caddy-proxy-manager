-- +goose Up
-- +goose StatementBegin
-- Empty scopes used to mean full access; they now grant nothing. Give every
-- legacy unscoped key the explicit set it effectively had so nothing breaks:
-- client-owned keys get the customer scopes, every other owner the full
-- admin-issued set (owner role and tenancy gates still apply on top).
UPDATE api_keys
   SET scopes = CASE
         WHEN (SELECT role FROM users WHERE users.id = api_keys.user_id) = 'client'
           THEN 'client:read,client:write'
         ELSE 'services,routes,nodes,admin:read,admin:write'
       END
 WHERE TRIM(scopes) = '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Data backfill; which keys were unscoped is not recoverable.
SELECT 1;
-- +goose StatementEnd
