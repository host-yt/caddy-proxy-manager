-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig79_up;
CREATE PROCEDURE hpg_mig79_up()
BEGIN
    -- 'off' = no geo rule emitted; 'allow' = only listed countries; 'deny' = block listed countries.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_mode') THEN
        ALTER TABLE routes ADD COLUMN geo_mode VARCHAR(8) NOT NULL DEFAULT 'off' AFTER waf_directives;
    END IF;
    -- Comma-separated uppercase ISO 3166-1 alpha-2 codes, e.g. "PL,DE,US".
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_countries') THEN
        ALTER TABLE routes ADD COLUMN geo_countries VARCHAR(512) NOT NULL DEFAULT '' AFTER geo_mode;
    END IF;
END;
CALL hpg_mig79_up();
DROP PROCEDURE hpg_mig79_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig79_down;
CREATE PROCEDURE hpg_mig79_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_countries') THEN
        ALTER TABLE routes DROP COLUMN geo_countries;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='geo_mode') THEN
        ALTER TABLE routes DROP COLUMN geo_mode;
    END IF;
END;
CALL hpg_mig79_down();
DROP PROCEDURE hpg_mig79_down;
-- +goose StatementEnd
