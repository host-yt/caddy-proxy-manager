-- +goose Up
-- +goose StatementBegin

-- SSO jump-login settings for external systems (FOSSBilling etc.).
-- sso_jump.secret_e2 is AES-GCM encrypted at rest.
DROP PROCEDURE IF EXISTS hpg_mig27_up;
CREATE PROCEDURE hpg_mig27_up()
BEGIN
    -- Guard: only insert rows that don't already exist.
    IF NOT EXISTS (SELECT 1 FROM settings WHERE `key` = 'sso_jump.enabled') THEN
        INSERT INTO settings (`key`, value) VALUES ('sso_jump.enabled', '0');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM settings WHERE `key` = 'sso_jump.allow_admin_login') THEN
        INSERT INTO settings (`key`, value) VALUES ('sso_jump.allow_admin_login', '0');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM settings WHERE `key` = 'sso_jump.secret_e2') THEN
        INSERT INTO settings (`key`, value, is_encrypted) VALUES ('sso_jump.secret_e2', '', 1);
    END IF;
END;
CALL hpg_mig27_up();
DROP PROCEDURE hpg_mig27_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE `key` IN ('sso_jump.enabled', 'sso_jump.allow_admin_login', 'sso_jump.secret_e2');
-- +goose StatementEnd
