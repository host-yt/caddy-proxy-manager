-- +goose Up
-- +goose StatementBegin

-- HTTP Basic Auth gate per route (NPM-style). Operator sets a
-- username + password; Caddy returns 401 until the browser sends
-- matching Basic creds. Single user per route - multi-user is rare
-- and adds UI complexity for little gain.
--
-- Stored as bcrypt hash (Caddy's basic_auth handler accepts bcrypt
-- natively, so the panel writes the hash verbatim into the handler).

DROP PROCEDURE IF EXISTS hpg_mig24_up;
CREATE PROCEDURE hpg_mig24_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='basic_auth_user') THEN
        ALTER TABLE routes ADD COLUMN basic_auth_user VARCHAR(64) NULL AFTER custom_config;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='basic_auth_bcrypt') THEN
        ALTER TABLE routes ADD COLUMN basic_auth_bcrypt VARCHAR(120) NULL AFTER basic_auth_user;
    END IF;
END;
CALL hpg_mig24_up();
DROP PROCEDURE hpg_mig24_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig24_down;
CREATE PROCEDURE hpg_mig24_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='basic_auth_bcrypt') THEN
        ALTER TABLE routes DROP COLUMN basic_auth_bcrypt;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='basic_auth_user') THEN
        ALTER TABLE routes DROP COLUMN basic_auth_user;
    END IF;
END;
CALL hpg_mig24_down();
DROP PROCEDURE hpg_mig24_down;
-- +goose StatementEnd
