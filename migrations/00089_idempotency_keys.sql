-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig89_up;
CREATE PROCEDURE hpg_mig89_up()
BEGIN
    -- idempotency_keys stores the stored response for POST provisioning calls
    -- so callers can retry safely without double-creating resources.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='idempotency_keys') THEN
        CREATE TABLE idempotency_keys (
            id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            idem_key        VARCHAR(128)    NOT NULL,
            user_id         BIGINT UNSIGNED NOT NULL,
            method          VARCHAR(10)     NOT NULL DEFAULT 'POST',
            path            VARCHAR(512)    NOT NULL,
            response_status SMALLINT        NOT NULL DEFAULT 200,
            response_body   MEDIUMTEXT      NOT NULL,
            created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at      TIMESTAMP       NOT NULL,
            UNIQUE KEY uq_idem (idem_key, user_id),
            KEY idx_idem_exp (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig89_up();
DROP PROCEDURE IF EXISTS hpg_mig89_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig89_down;
CREATE PROCEDURE hpg_mig89_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='idempotency_keys') THEN
        DROP TABLE idempotency_keys;
    END IF;
END;
CALL hpg_mig89_down();
DROP PROCEDURE IF EXISTS hpg_mig89_down;
-- +goose StatementEnd
