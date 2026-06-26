-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig64_up;
CREATE PROCEDURE hpg_mig64_up()
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'plans'
          AND COLUMN_NAME = 'allow_egress_ip'
    ) THEN
        ALTER TABLE plans ADD COLUMN allow_egress_ip TINYINT(1) NOT NULL DEFAULT 0;
    END IF;

    ALTER TABLE routes MODIFY outbound_ip_mode ENUM('default','fixed','random') NOT NULL DEFAULT 'default';
END;
CALL hpg_mig64_up();
DROP PROCEDURE hpg_mig64_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig64_down;
CREATE PROCEDURE hpg_mig64_down()
BEGIN
    -- Clear 'random' rows before narrowing the enum to avoid truncation errors on rollback.
    UPDATE routes SET outbound_ip_mode='default', outbound_ip=NULL WHERE outbound_ip_mode='random';
    ALTER TABLE routes MODIFY outbound_ip_mode ENUM('default','fixed') NOT NULL DEFAULT 'default';

    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'plans'
          AND COLUMN_NAME = 'allow_egress_ip'
    ) THEN
        ALTER TABLE plans DROP COLUMN allow_egress_ip;
    END IF;
END;
CALL hpg_mig64_down();
DROP PROCEDURE hpg_mig64_down;
-- +goose StatementEnd
