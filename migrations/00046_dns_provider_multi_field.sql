-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig46_up;
CREATE PROCEDURE hpg_mig46_up()
BEGIN
    -- Multi-provider DNS-01: api_token_enc now holds an AES-256-GCM JSON blob
    -- of the provider's full credential field map (was a single token). A
    -- multi-field provider (e.g. a GCP service-account JSON) overflows the
    -- old VARCHAR(1024), so widen to TEXT. Legacy cloudflare rows (bare token)
    -- still decode via the JSON-or-bare compat path - no data rewrite needed.
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_providers' AND COLUMN_NAME='api_token_enc' AND DATA_TYPE='varchar') THEN
        ALTER TABLE dns_providers MODIFY COLUMN api_token_enc TEXT NOT NULL;
    END IF;
    -- provider slug column widened: registry slugs (e.g. "googleclouddns") fit
    -- 32 already, but bump for headroom and to drop the old cloudflare default.
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_providers' AND COLUMN_NAME='provider' AND CHARACTER_MAXIMUM_LENGTH < 64) THEN
        ALTER TABLE dns_providers MODIFY COLUMN provider VARCHAR(64) NOT NULL DEFAULT 'cloudflare';
    END IF;
END;
CALL hpg_mig46_up();
DROP PROCEDURE hpg_mig46_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig46_down;
CREATE PROCEDURE hpg_mig46_down()
BEGIN
    -- Revert column widths. TEXT->VARCHAR(1024) may truncate multi-field blobs;
    -- acceptable on a down-migration (pre-multi-provider state).
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_providers' AND COLUMN_NAME='api_token_enc' AND DATA_TYPE='text') THEN
        ALTER TABLE dns_providers MODIFY COLUMN api_token_enc VARCHAR(1024) NOT NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='dns_providers' AND COLUMN_NAME='provider' AND CHARACTER_MAXIMUM_LENGTH > 32) THEN
        ALTER TABLE dns_providers MODIFY COLUMN provider VARCHAR(32) NOT NULL DEFAULT 'cloudflare';
    END IF;
END;
CALL hpg_mig46_down();
DROP PROCEDURE hpg_mig46_down;
-- +goose StatementEnd
