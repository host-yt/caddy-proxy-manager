-- +goose Up
ALTER TABLE routes
    ADD COLUMN IF NOT EXISTS sso_strict_mode TINYINT(1) NOT NULL DEFAULT 0 AFTER sso_provider_url;

-- +goose Down
ALTER TABLE routes DROP COLUMN IF EXISTS sso_strict_mode;
