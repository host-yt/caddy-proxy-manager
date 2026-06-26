-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig82_up;
CREATE PROCEDURE hpg_mig82_up()
BEGIN
    -- Persist the last refresh failure so the admin UI can show WHY a download
    -- failed instead of a silent "no database" (e.g. EACCES on the volume).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='geoip_db_meta' AND COLUMN_NAME='last_error') THEN
        ALTER TABLE geoip_db_meta ADD COLUMN last_error VARCHAR(512) NOT NULL DEFAULT '';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='geoip_db_meta' AND COLUMN_NAME='last_attempt_at') THEN
        ALTER TABLE geoip_db_meta ADD COLUMN last_attempt_at DATETIME NULL;
    END IF;
END;
CALL hpg_mig82_up();
DROP PROCEDURE hpg_mig82_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig82_down;
CREATE PROCEDURE hpg_mig82_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='geoip_db_meta' AND COLUMN_NAME='last_error') THEN
        ALTER TABLE geoip_db_meta DROP COLUMN last_error;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='geoip_db_meta' AND COLUMN_NAME='last_attempt_at') THEN
        ALTER TABLE geoip_db_meta DROP COLUMN last_attempt_at;
    END IF;
END;
CALL hpg_mig82_down();
DROP PROCEDURE hpg_mig82_down;
-- +goose StatementEnd
