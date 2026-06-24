-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig52_up;
CREATE PROCEDURE hpg_mig52_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_access_log') THEN
        CREATE TABLE host_access_log (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            route_id   BIGINT         NOT NULL,
            ts         DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
            method     VARCHAR(16)    NOT NULL DEFAULT '',
            uri        VARCHAR(2048)  NOT NULL DEFAULT '',
            status     SMALLINT       NOT NULL DEFAULT 0,
            latency_ms INT            NOT NULL DEFAULT 0,
            remote_ip  VARCHAR(45)    NOT NULL DEFAULT '',
            user_agent VARCHAR(512)   NOT NULL DEFAULT '',
            PRIMARY KEY (id),
            KEY idx_hal_route_ts (route_id, ts DESC)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig52_up();
DROP PROCEDURE hpg_mig52_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS host_access_log;
-- +goose StatementEnd
