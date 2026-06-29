-- +goose Up
-- Per-client geo-block response: each client can customise the page shown
-- (or redirect target) when a request is geo/CIDR-blocked. Empty action means
-- inherit the panel-wide default stored in the settings table (geoblock.*).
ALTER TABLE clients
    ADD COLUMN geo_block_action       VARCHAR(16)  NOT NULL DEFAULT '',
    ADD COLUMN geo_block_redirect_url VARCHAR(512) NOT NULL DEFAULT '',
    ADD COLUMN geo_block_title        VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN geo_block_message      TEXT,
    ADD COLUMN geo_block_logo_url     VARCHAR(512) NOT NULL DEFAULT '',
    ADD COLUMN geo_block_bg_color     VARCHAR(32)  NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE clients
    DROP COLUMN geo_block_bg_color,
    DROP COLUMN geo_block_logo_url,
    DROP COLUMN geo_block_message,
    DROP COLUMN geo_block_title,
    DROP COLUMN geo_block_redirect_url,
    DROP COLUMN geo_block_action;
