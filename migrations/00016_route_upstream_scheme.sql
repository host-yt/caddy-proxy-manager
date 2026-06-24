-- +goose Up
ALTER TABLE routes
  ADD COLUMN upstream_scheme ENUM('http','https') NOT NULL DEFAULT 'http' AFTER upstream_port;

-- +goose Down
ALTER TABLE routes
  DROP COLUMN upstream_scheme;
