-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig47_up;
CREATE PROCEDURE hpg_mig47_up()
BEGIN
    -- Per-route override of the node-wide maintenance / error branding so a
    -- customer's hosts can render their own down page. Admin-set only.
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'routes' AND column_name = 'error_override') THEN
        ALTER TABLE routes
            ADD COLUMN error_override TINYINT(1) NOT NULL DEFAULT 0,
            ADD COLUMN error_html     MEDIUMTEXT NULL,
            ADD COLUMN error_logo_url VARCHAR(512) NULL,
            ADD COLUMN error_brand    VARCHAR(128) NULL,
            ADD COLUMN error_bg_color VARCHAR(32)  NULL;
    END IF;
END;
CALL hpg_mig47_up();
DROP PROCEDURE hpg_mig47_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig47_down;
CREATE PROCEDURE hpg_mig47_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = 'routes' AND column_name = 'error_override') THEN
        ALTER TABLE routes
            DROP COLUMN error_override, DROP COLUMN error_html,
            DROP COLUMN error_logo_url, DROP COLUMN error_brand, DROP COLUMN error_bg_color;
    END IF;
END;
CALL hpg_mig47_down();
DROP PROCEDURE hpg_mig47_down;
-- +goose StatementEnd
