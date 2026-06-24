-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig35_up;
CREATE PROCEDURE hpg_mig35_up()
BEGIN
    -- Discriminator: this proxy route targets an allowlisted external host;
    -- the builder enforces SNI + Host rewrite + inbound bearer secret.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='upstream_external') THEN
        ALTER TABLE routes ADD COLUMN upstream_external TINYINT(1) NOT NULL DEFAULT 0 AFTER backend_ip_override;
    END IF;
    -- Value used for BOTH tls.server_name (SNI) and the upstream Host header.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='upstream_host_header') THEN
        ALTER TABLE routes ADD COLUMN upstream_host_header VARCHAR(255) NULL AFTER upstream_external;
    END IF;
    -- Inbound bearer secret, AES-256-GCM encrypted at rest (base64). The
    -- builder decrypts it to emit the node-side 403 matcher; plaintext is
    -- shown to the operator once at creation and never stored in the clear.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='proxy_secret_enc') THEN
        ALTER TABLE routes ADD COLUMN proxy_secret_enc VARCHAR(512) NULL AFTER upstream_host_header;
    END IF;
END;
CALL hpg_mig35_up();
DROP PROCEDURE hpg_mig35_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig35_down;
CREATE PROCEDURE hpg_mig35_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='proxy_secret_enc') THEN
        ALTER TABLE routes DROP COLUMN proxy_secret_enc;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='upstream_host_header') THEN
        ALTER TABLE routes DROP COLUMN upstream_host_header;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='upstream_external') THEN
        ALTER TABLE routes DROP COLUMN upstream_external;
    END IF;
END;
CALL hpg_mig35_down();
DROP PROCEDURE hpg_mig35_down;
-- +goose StatementEnd
