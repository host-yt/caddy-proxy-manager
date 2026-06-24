-- +goose Up
ALTER TABLE routes
  ADD COLUMN cache_vary VARCHAR(255) NULL AFTER cache_ttl_secs;

-- +goose Down
ALTER TABLE routes
  DROP COLUMN cache_vary;
