-- +goose Up
-- +goose StatementBegin
-- SEC-006: one route's custom SecLang could make the node's /load fail for
-- every tenant on it. A rejected route's directives are parked here so the
-- rest of the node publishes, and the hash lets an edited directive set get
-- another chance without anyone having to clear the flag by hand.
DROP PROCEDURE IF EXISTS hpg_mig160_up;
CREATE PROCEDURE hpg_mig160_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_quarantined_at') THEN
        ALTER TABLE routes ADD COLUMN waf_quarantined_at DATETIME NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_quarantine_reason') THEN
        ALTER TABLE routes ADD COLUMN waf_quarantine_reason TEXT NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_quarantine_fingerprint') THEN
        ALTER TABLE routes ADD COLUMN waf_quarantine_fingerprint VARCHAR(64) NULL;
    END IF;
END;
CALL hpg_mig160_up();
DROP PROCEDURE IF EXISTS hpg_mig160_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig160_down;
CREATE PROCEDURE hpg_mig160_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_quarantined_at') THEN
        ALTER TABLE routes DROP COLUMN waf_quarantined_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_quarantine_reason') THEN
        ALTER TABLE routes DROP COLUMN waf_quarantine_reason;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='waf_quarantine_fingerprint') THEN
        ALTER TABLE routes DROP COLUMN waf_quarantine_fingerprint;
    END IF;
END;
CALL hpg_mig160_down();
DROP PROCEDURE IF EXISTS hpg_mig160_down;
-- +goose StatementEnd
