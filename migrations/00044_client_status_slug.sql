-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig44_up;
CREATE PROCEDURE hpg_mig44_up()
BEGIN
    -- Opaque random token (32 hex chars) addressing the public status page.
    -- NULL = page disabled. Not a secret; security via obscurity + rate-limit.
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
          AND COLUMN_NAME='status_slug'
    ) THEN
        ALTER TABLE clients
            ADD COLUMN status_slug CHAR(32) NULL AFTER display_name,
            ADD UNIQUE KEY uq_clients_status_slug (status_slug);
    END IF;
    -- Per-client opt-in to expose traffic bytes and sparkline on the page.
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
          AND COLUMN_NAME='status_show_traffic'
    ) THEN
        ALTER TABLE clients
            ADD COLUMN status_show_traffic TINYINT(1) NOT NULL DEFAULT 0
            AFTER status_slug;
    END IF;
END;
CALL hpg_mig44_up();
DROP PROCEDURE hpg_mig44_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig44_down;
CREATE PROCEDURE hpg_mig44_down()
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
          AND INDEX_NAME='uq_clients_status_slug'
    ) THEN
        ALTER TABLE clients DROP KEY uq_clients_status_slug;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
          AND COLUMN_NAME='status_show_traffic'
    ) THEN
        ALTER TABLE clients DROP COLUMN status_show_traffic;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
          AND COLUMN_NAME='status_slug'
    ) THEN
        ALTER TABLE clients DROP COLUMN status_slug;
    END IF;
END;
CALL hpg_mig44_down();
DROP PROCEDURE hpg_mig44_down;
-- +goose StatementEnd
