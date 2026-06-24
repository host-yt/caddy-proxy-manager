-- +goose Up
-- +goose StatementBegin

-- Per-route forward-auth SSO (Authentik / Authelia / generic). When
-- sso_provider_url is set, BuildRoute emits a subroute that:
--   1. proxies /outpost.goauthentik.io/* to the provider (auth flow)
--   2. forward_auth's every other request to <provider>/auth/caddy
--   3. only forwards to upstream when forward_auth returns 2xx
-- sso_copy_headers is a newline-separated list of headers to lift from
-- the auth subresponse into the upstream request (X-Authentik-User,
-- X-Authentik-Groups, ...).
-- sso_trusted_proxies caps which networks are trusted to set
-- X-Forwarded-* on the auth subrequest.

DROP PROCEDURE IF EXISTS hpg_mig25_up;
CREATE PROCEDURE hpg_mig25_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_provider_url') THEN
        ALTER TABLE routes ADD COLUMN sso_provider_url VARCHAR(255) NULL AFTER basic_auth_bcrypt;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_copy_headers') THEN
        ALTER TABLE routes ADD COLUMN sso_copy_headers TEXT NULL AFTER sso_provider_url;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_trusted_proxies') THEN
        ALTER TABLE routes ADD COLUMN sso_trusted_proxies VARCHAR(255) NULL AFTER sso_copy_headers;
    END IF;
END;
CALL hpg_mig25_up();
DROP PROCEDURE hpg_mig25_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig25_down;
CREATE PROCEDURE hpg_mig25_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_trusted_proxies') THEN
        ALTER TABLE routes DROP COLUMN sso_trusted_proxies;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_copy_headers') THEN
        ALTER TABLE routes DROP COLUMN sso_copy_headers;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_provider_url') THEN
        ALTER TABLE routes DROP COLUMN sso_provider_url;
    END IF;
END;
CALL hpg_mig25_down();
DROP PROCEDURE hpg_mig25_down;
-- +goose StatementEnd
