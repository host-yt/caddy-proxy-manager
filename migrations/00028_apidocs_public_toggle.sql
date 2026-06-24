-- +goose Up
-- +goose StatementBegin

-- Toggle whether /api-docs (Scalar) is reachable without a session.
-- Default '1' for backwards-compat (existing deploys already expose it).
-- Operator can flip to '0' in /admin/settings to require admin login,
-- useful when the panel runs on a public hostname and the operator
-- doesn't want to leak the API surface to anonymous visitors.

DROP PROCEDURE IF EXISTS hpg_mig28_up;
CREATE PROCEDURE hpg_mig28_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM settings WHERE `key` = 'apidocs.public_enabled') THEN
        INSERT INTO settings (`key`, value) VALUES ('apidocs.public_enabled', '1');
    END IF;
END;
CALL hpg_mig28_up();
DROP PROCEDURE hpg_mig28_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE `key` = 'apidocs.public_enabled';
-- +goose StatementEnd
