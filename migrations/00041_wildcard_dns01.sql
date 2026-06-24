-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig41_up;
CREATE PROCEDURE hpg_mig41_up()
BEGIN
    -- Per-zone DNS-provider credential for ACME DNS-01 wildcard issuance.
    -- api_token_enc is AES-256-GCM (APP_SECRET) base64, decrypted only at
    -- build time into the node config; never logged or returned.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_providers') THEN
        CREATE TABLE dns_providers (
          id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          name          VARCHAR(253)  NOT NULL,            -- apex zone, e.g. "customer.com"
          provider      VARCHAR(32)   NOT NULL DEFAULT 'cloudflare',
          api_token_enc VARCHAR(1024) NOT NULL,            -- AES-256-GCM base64
          created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY uq_dns_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
    -- This route's domain is served by a *.zone cert obtained via DNS-01.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='wildcard_enabled') THEN
        ALTER TABLE routes ADD COLUMN wildcard_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER proxy_secret_enc;
    END IF;
    -- Apex zone whose wildcard covers this route; FK-less ref to dns_providers.name.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='wildcard_zone') THEN
        ALTER TABLE routes ADD COLUMN wildcard_zone VARCHAR(253) NULL AFTER wildcard_enabled;
    END IF;
    -- Plan gate: customers may only enable wildcard routes when their plan
    -- allows it (admin/API context bypasses). routes.Create SELECTs this.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='wildcard_enabled') THEN
        ALTER TABLE plans ADD COLUMN wildcard_enabled TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig41_up();
DROP PROCEDURE hpg_mig41_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig41_down;
CREATE PROCEDURE hpg_mig41_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='wildcard_enabled') THEN
        ALTER TABLE plans DROP COLUMN wildcard_enabled;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='wildcard_zone') THEN
        ALTER TABLE routes DROP COLUMN wildcard_zone;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='wildcard_enabled') THEN
        ALTER TABLE routes DROP COLUMN wildcard_enabled;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_providers') THEN
        DROP TABLE dns_providers;
    END IF;
END;
CALL hpg_mig41_down();
DROP PROCEDURE hpg_mig41_down;
-- +goose StatementEnd
