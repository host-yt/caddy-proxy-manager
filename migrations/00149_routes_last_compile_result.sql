-- +goose Up
-- +goose StatementBegin
-- The compiler could quarantine a route or refuse its target while the record
-- still read "active" in the UI; the cause only existed in the log and the
-- audit trail (HPG-022). Empty status means "never compiled since upgrade" -
-- deliberately not backfilled as "ok", which would claim a check that never ran.
DROP PROCEDURE IF EXISTS hpg_mig149_up;
CREATE PROCEDURE hpg_mig149_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='last_compile_status') THEN
        ALTER TABLE routes ADD COLUMN last_compile_status VARCHAR(32) NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='last_compile_reason') THEN
        ALTER TABLE routes ADD COLUMN last_compile_reason TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='last_compile_at') THEN
        ALTER TABLE routes ADD COLUMN last_compile_at DATETIME NULL;
    END IF;
END;
CALL hpg_mig149_up();
DROP PROCEDURE IF EXISTS hpg_mig149_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig149_down;
CREATE PROCEDURE hpg_mig149_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='last_compile_status') THEN
        ALTER TABLE routes DROP COLUMN last_compile_status;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='last_compile_reason') THEN
        ALTER TABLE routes DROP COLUMN last_compile_reason;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='last_compile_at') THEN
        ALTER TABLE routes DROP COLUMN last_compile_at;
    END IF;
END;
CALL hpg_mig149_down();
DROP PROCEDURE IF EXISTS hpg_mig149_down;
-- +goose StatementEnd
