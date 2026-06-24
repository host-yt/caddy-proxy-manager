-- +goose Up
-- NPM-style multi-domain: aliases is a comma-separated list of additional
-- hostnames that share the route. Primary `domain` keeps DNS-check + cert
-- tracking semantics; aliases inherit on-demand TLS via /internal/ask.
ALTER TABLE routes
    ADD COLUMN aliases TEXT NULL AFTER domain;

-- +goose Down
ALTER TABLE routes DROP COLUMN aliases;
