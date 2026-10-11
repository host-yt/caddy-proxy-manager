-- +goose Up
-- Older installers put the tunnel bootstrap token in /api/wg/* query strings; drop them from stored logs.
-- +goose StatementBegin
UPDATE host_access_log SET uri = SUBSTRING_INDEX(uri, '?', 1) WHERE uri LIKE '/api/wg/%?%';
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE waf_events SET uri = SUBSTRING_INDEX(uri, '?', 1) WHERE uri LIKE '/api/wg/%?%';
-- +goose StatementEnd

-- +goose Down
-- Redaction is one-way.
SELECT 1;
