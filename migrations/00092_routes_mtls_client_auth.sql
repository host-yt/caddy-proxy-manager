-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig92_up;
CREATE PROCEDURE hpg_mig92_up()
BEGIN
    -- Per-host mTLS client-cert enforcement. require_client_cert flips the
    -- Caddy TLS connection policy to require_and_verify; mtls_ca_id selects the
    -- trust anchor (FK to mtls_cas). BIGINT UNSIGNED to match mtls_cas.id PK -
    -- a signed FK fails at runtime with MySQL 3780 and crash-loops the app.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='require_client_cert') THEN
        ALTER TABLE routes ADD COLUMN require_client_cert TINYINT NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='mtls_ca_id') THEN
        ALTER TABLE routes ADD COLUMN mtls_ca_id BIGINT UNSIGNED NULL;
    END IF;
    -- ON DELETE SET NULL so deleting a CA disables enforcement on its hosts
    -- (build then falls back to no client-auth) instead of orphaning a FK.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_routes_mtls_ca') THEN
        ALTER TABLE routes
            ADD CONSTRAINT fk_routes_mtls_ca FOREIGN KEY (mtls_ca_id)
            REFERENCES mtls_cas(id) ON DELETE SET NULL;
    END IF;
END;
CALL hpg_mig92_up();
DROP PROCEDURE IF EXISTS hpg_mig92_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig92_down;
CREATE PROCEDURE hpg_mig92_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_routes_mtls_ca') THEN
        ALTER TABLE routes DROP FOREIGN KEY fk_routes_mtls_ca;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='mtls_ca_id') THEN
        ALTER TABLE routes DROP COLUMN mtls_ca_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='require_client_cert') THEN
        ALTER TABLE routes DROP COLUMN require_client_cert;
    END IF;
END;
CALL hpg_mig92_down();
DROP PROCEDURE IF EXISTS hpg_mig92_down;
-- +goose StatementEnd
