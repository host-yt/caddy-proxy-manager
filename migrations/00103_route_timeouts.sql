-- +goose Up
ALTER TABLE routes
  ADD COLUMN dial_timeout_ms INT NOT NULL DEFAULT 0,
  ADD COLUMN response_header_timeout_ms INT NOT NULL DEFAULT 0;
-- +goose Down
ALTER TABLE routes
  DROP COLUMN dial_timeout_ms,
  DROP COLUMN response_header_timeout_ms;
