-- +goose Up
-- +goose StatementBegin
-- SEC-002: an unauthenticated control plane is now a per-node, opt-in legacy
-- allowance instead of the silent fleet-wide default. Existing keyless nodes
-- are grandfathered so an upgrade does not brick a fleet mid-migration; nodes
-- registered after this point start at 0 and fail closed.
DROP PROCEDURE IF EXISTS hpg_mig159_up;
CREATE PROCEDURE hpg_mig159_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='allow_unauthenticated_admin') THEN
        ALTER TABLE caddy_nodes ADD COLUMN allow_unauthenticated_admin TINYINT(1) NOT NULL DEFAULT 0;
        UPDATE caddy_nodes SET allow_unauthenticated_admin = 1
         WHERE admin_proxy_key_enc IS NULL OR admin_proxy_key_enc = '';
    END IF;
END;
CALL hpg_mig159_up();
DROP PROCEDURE IF EXISTS hpg_mig159_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig159_down;
CREATE PROCEDURE hpg_mig159_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='allow_unauthenticated_admin') THEN
        ALTER TABLE caddy_nodes DROP COLUMN allow_unauthenticated_admin;
    END IF;
END;
CALL hpg_mig159_down();
DROP PROCEDURE IF EXISTS hpg_mig159_down;
-- +goose StatementEnd
