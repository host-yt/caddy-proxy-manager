-- +goose Up
-- +goose StatementBegin
-- Explicit "this content does not depend on the caller" opt-in. Caching is
-- default-private: the panel cannot see auth an upstream does itself (cookie
-- session, bearer, API key), so only an operator can declare a route public.
-- Existing cached routes default to 0 and stop being shared-cacheable.
DROP PROCEDURE IF EXISTS hpg_mig133_up;
CREATE PROCEDURE hpg_mig133_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='cache_public') THEN
        ALTER TABLE routes ADD COLUMN cache_public TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig133_up();
DROP PROCEDURE IF EXISTS hpg_mig133_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig133_down;
CREATE PROCEDURE hpg_mig133_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='cache_public') THEN
        ALTER TABLE routes DROP COLUMN cache_public;
    END IF;
END;
CALL hpg_mig133_down();
DROP PROCEDURE IF EXISTS hpg_mig133_down;
-- +goose StatementEnd
