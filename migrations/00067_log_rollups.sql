-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig67_up;
CREATE PROCEDURE hpg_mig67_up()
BEGIN
    -- Hourly aggregate buckets so rollup data survives raw-log prune.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='log_rollups') THEN
        CREATE TABLE log_rollups (
            route_id        BIGINT          NOT NULL,
            bucket_start    DATETIME        NOT NULL,
            requests        INT UNSIGNED    NOT NULL DEFAULT 0,
            errors_4xx      INT UNSIGNED    NOT NULL DEFAULT 0,
            errors_5xx      INT UNSIGNED    NOT NULL DEFAULT 0,
            latency_sum_ms  BIGINT UNSIGNED NOT NULL DEFAULT 0,
            latency_max_ms  INT UNSIGNED    NOT NULL DEFAULT 0,
            PRIMARY KEY (route_id, bucket_start)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig67_up();
DROP PROCEDURE hpg_mig67_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS log_rollups;
-- +goose StatementEnd
