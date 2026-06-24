-- +goose Up
ALTER TABLE routes
  ADD COLUMN maintenance_mode    TINYINT(1) NOT NULL DEFAULT 0 AFTER cache_ttl_secs,
  ADD COLUMN maintenance_message VARCHAR(500) NULL          AFTER maintenance_mode;

-- +goose Down
ALTER TABLE routes
  DROP COLUMN maintenance_message,
  DROP COLUMN maintenance_mode;
