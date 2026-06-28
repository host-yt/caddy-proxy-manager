-- +goose Up
ALTER TABLE routes
    ADD COLUMN geo_continents  VARCHAR(50)  NOT NULL DEFAULT '' AFTER geo_allow_cidrs,
    ADD COLUMN geo_block_cidrs TEXT                  DEFAULT NULL AFTER geo_continents;

-- +goose Down
ALTER TABLE routes
    DROP COLUMN geo_block_cidrs,
    DROP COLUMN geo_continents;
