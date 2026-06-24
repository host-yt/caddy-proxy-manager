-- +goose Up
ALTER TABLE routes
    ADD COLUMN upstream_skip_tls_verify TINYINT(1) NOT NULL DEFAULT 0 AFTER upstream_scheme;

-- +goose Down
ALTER TABLE routes DROP COLUMN upstream_skip_tls_verify;
