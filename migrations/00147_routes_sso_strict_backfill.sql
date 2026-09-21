-- +goose Up
-- +goose StatementBegin
-- Every SSO-protected route is moved to strict mode. Permissive mode gates
-- document loads only, so a route left on it was protected for browsing and
-- open for everything else. It stays available as a per-route opt-out an
-- operator has to choose again deliberately.
-- `server doctor` lists the affected routes before the upgrade runs.
UPDATE routes
   SET sso_strict_mode = 1
 WHERE COALESCE(sso_provider_url, '') <> ''
   AND COALESCE(sso_strict_mode, 0) = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Data backfill; the previous per-row values are not recoverable.
SELECT 1;
-- +goose StatementEnd
