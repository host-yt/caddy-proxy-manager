-- +goose Up
-- +goose StatementBegin
-- Why a route is disabled. NULL = an operator turned it off by hand;
-- 'service_suspended'/'service_terminated' = the owning service's lifecycle
-- did. Resume may only re-enable the second kind (HPG-007).
DROP PROCEDURE IF EXISTS hpg_mig152_up;
CREATE PROCEDURE hpg_mig152_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='disabled_reason') THEN
        ALTER TABLE routes ADD COLUMN disabled_reason VARCHAR(32) NULL;
    END IF;
END;
CALL hpg_mig152_up();
DROP PROCEDURE IF EXISTS hpg_mig152_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig152_down;
CREATE PROCEDURE hpg_mig152_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='disabled_reason') THEN
        ALTER TABLE routes DROP COLUMN disabled_reason;
    END IF;
END;
CALL hpg_mig152_down();
DROP PROCEDURE IF EXISTS hpg_mig152_down;
-- +goose StatementEnd
