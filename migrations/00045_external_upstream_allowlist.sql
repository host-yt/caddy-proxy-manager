-- +goose Up
-- +goose StatementBegin
-- DB-managed allowlist of external upstream FQDNs an External proxy route may
-- target. Augments (union with) the env EXTERNAL_UPSTREAM_ALLOWLIST CSV so the
-- operator can manage the open-relay allowlist from the UI without a restart.
CREATE TABLE IF NOT EXISTS external_upstream_allowlist (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    host       VARCHAR(255) NOT NULL,
    note       VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_external_upstream_allowlist_host (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig45_up;
CREATE PROCEDURE hpg_mig45_up()
BEGIN
    -- Per-plan gate: may users on this plan create external-upstream routes.
    -- Default 0 (module gate off); NPM-kind plans (the admin-self plan) are
    -- enabled below so super_admin works out of the box.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='external_proxy_enabled') THEN
        ALTER TABLE plans ADD COLUMN external_proxy_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER wildcard_enabled;
        UPDATE plans SET external_proxy_enabled = 1 WHERE kind = 'npm';
    END IF;
END;
CALL hpg_mig45_up();
DROP PROCEDURE hpg_mig45_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig45_down;
CREATE PROCEDURE hpg_mig45_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='external_proxy_enabled') THEN
        ALTER TABLE plans DROP COLUMN external_proxy_enabled;
    END IF;
END;
CALL hpg_mig45_down();
DROP PROCEDURE hpg_mig45_down;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS external_upstream_allowlist;
-- +goose StatementEnd
