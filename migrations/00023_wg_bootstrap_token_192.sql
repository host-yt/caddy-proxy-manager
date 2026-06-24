-- +goose Up
-- +goose StatementBegin

-- Bump bootstrap token from 64 hex chars (256-bit) to 192 hex chars
-- (768-bit). 256-bit is already cryptographically out of reach for
-- brute force, but operator preference: longer = harder to guess at a
-- glance + smaller chance of accidental URL truncation in chat clients
-- that hard-wrap fixed widths. VARCHAR(192) avoids padding overhead.

DROP PROCEDURE IF EXISTS hpg_mig23_up;
CREATE PROCEDURE hpg_mig23_up()
BEGIN
    -- Token column may not exist yet on fresh installs that skipped
    -- mig 20 partial state - guard with information_schema.
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE()
                 AND TABLE_NAME='customer_wg_bootstrap'
                 AND COLUMN_NAME='token'
                 AND CHARACTER_MAXIMUM_LENGTH < 192) THEN
        ALTER TABLE customer_wg_bootstrap MODIFY token VARCHAR(192) NOT NULL;
    END IF;
END;
CALL hpg_mig23_up();
DROP PROCEDURE hpg_mig23_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig23_down;
CREATE PROCEDURE hpg_mig23_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE()
                 AND TABLE_NAME='customer_wg_bootstrap'
                 AND COLUMN_NAME='token'
                 AND CHARACTER_MAXIMUM_LENGTH > 64) THEN
        -- Wipe rows we can't shrink-fit, then revert width.
        DELETE FROM customer_wg_bootstrap WHERE CHAR_LENGTH(token) > 64;
        ALTER TABLE customer_wg_bootstrap MODIFY token CHAR(64) NOT NULL;
    END IF;
END;
CALL hpg_mig23_down();
DROP PROCEDURE hpg_mig23_down;
-- +goose StatementEnd
