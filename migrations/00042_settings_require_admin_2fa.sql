-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig42_up;
CREATE PROCEDURE hpg_mig42_up()
BEGIN
    -- Seed the runtime toggle row (value '0' = off). Insert only if absent so
    -- repeated runs are idempotent. The env REQUIRE_ADMIN_2FA still overrides.
    IF NOT EXISTS (SELECT 1 FROM settings WHERE `key` = 'security.require_admin_2fa') THEN
        INSERT INTO settings (`key`, `value`) VALUES ('security.require_admin_2fa', '0');
    END IF;
END;
CALL hpg_mig42_up();
DROP PROCEDURE hpg_mig42_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE `key` = 'security.require_admin_2fa';
-- +goose StatementEnd
