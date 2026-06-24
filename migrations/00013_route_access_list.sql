-- +goose Up
ALTER TABLE routes
  ADD COLUMN access_allow TEXT NULL AFTER cache_vary,
  ADD COLUMN access_deny  TEXT NULL AFTER access_allow;

-- +goose Down
ALTER TABLE routes
  DROP COLUMN access_deny,
  DROP COLUMN access_allow;
