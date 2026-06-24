-- +goose Up
ALTER TABLE routes
  ADD COLUMN custom_config TEXT NULL AFTER access_deny;

-- +goose Down
ALTER TABLE routes
  DROP COLUMN custom_config;
