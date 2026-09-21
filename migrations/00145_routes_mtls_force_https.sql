-- +goose Up
-- +goose StatementBegin
-- An mTLS-enforced host is HTTPS-only: the node now derives the :80 redirect
-- from require_client_cert (BuildRoute) and every write path stores
-- force_https=1 alongside it. Backfill rows written before that so the panel
-- reads as what the node serves.
UPDATE routes SET force_https = 1
 WHERE COALESCE(require_client_cert, 0) = 1 AND COALESCE(force_https, 0) = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Data backfill; the previous per-row values are not recoverable.
SELECT 1;
-- +goose StatementEnd
