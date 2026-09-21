-- +goose Up
-- +goose StatementBegin
-- A reservation used to be indistinguishable from a crashed one: both read as
-- "pending", so a retry got 409 "in progress" for the full 24 h TTL while the
-- operation may already have been applied.
--
-- lease_until bounds how long a pending row is genuinely in flight; past it the
-- outcome is unknown, not in progress. operation_id is the durable handle for
-- one attempt, returned to the caller and logged, so an operation whose result
-- could not be recorded can still be reconciled instead of blindly retried.
DROP PROCEDURE IF EXISTS hpg_mig156_up;
CREATE PROCEDURE hpg_mig156_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='idempotency_keys' AND COLUMN_NAME='operation_id') THEN
        ALTER TABLE idempotency_keys ADD COLUMN operation_id VARCHAR(32) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='idempotency_keys' AND COLUMN_NAME='lease_until') THEN
        ALTER TABLE idempotency_keys ADD COLUMN lease_until TIMESTAMP NULL;
    END IF;
    -- Rows reserved before this migration have no lease. They are pending from
    -- a process that is no longer running, so they are unresolved (state 2),
    -- not in flight: a retry gets a definite answer and never re-executes.
    UPDATE idempotency_keys SET state = 2 WHERE state = 0 AND lease_until IS NULL;
END;
CALL hpg_mig156_up();
DROP PROCEDURE IF EXISTS hpg_mig156_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig156_down;
CREATE PROCEDURE hpg_mig156_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='idempotency_keys' AND COLUMN_NAME='lease_until') THEN
        ALTER TABLE idempotency_keys DROP COLUMN lease_until;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='idempotency_keys' AND COLUMN_NAME='operation_id') THEN
        ALTER TABLE idempotency_keys DROP COLUMN operation_id;
    END IF;
END;
CALL hpg_mig156_down();
DROP PROCEDURE IF EXISTS hpg_mig156_down;
-- +goose StatementEnd
