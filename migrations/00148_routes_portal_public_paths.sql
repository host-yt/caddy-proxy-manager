-- +goose Up
-- +goose StatementBegin
-- The portal gate used to exempt GET/HEAD under asset-looking paths (*.js,
-- /assets/*, ...) for every protected route. A path is not proof the resource
-- is public, so the exemption becomes an explicit per-route list of Caddy path
-- matchers. Empty (the default) means no exceptions at all (HPG-003).
DROP PROCEDURE IF EXISTS hpg_mig148_up;
CREATE PROCEDURE hpg_mig148_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='portal_public_paths') THEN
        ALTER TABLE routes ADD COLUMN portal_public_paths TEXT NULL;
    END IF;
END;
CALL hpg_mig148_up();
DROP PROCEDURE IF EXISTS hpg_mig148_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig148_down;
CREATE PROCEDURE hpg_mig148_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='portal_public_paths') THEN
        ALTER TABLE routes DROP COLUMN portal_public_paths;
    END IF;
END;
CALL hpg_mig148_down();
DROP PROCEDURE IF EXISTS hpg_mig148_down;
-- +goose StatementEnd
