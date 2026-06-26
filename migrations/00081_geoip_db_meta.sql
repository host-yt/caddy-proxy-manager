-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig81_up;
CREATE PROCEDURE hpg_mig81_up()
BEGIN
    -- Single-row table tracking the centrally-downloaded GeoLite2 mmdb so the
    -- panel job and node-agents can compare sha256 without re-reading the file.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='geoip_db_meta') THEN
        CREATE TABLE geoip_db_meta (
            id          TINYINT      NOT NULL DEFAULT 1,
            sha256      CHAR(64)     NOT NULL DEFAULT '',
            size_bytes  BIGINT       NOT NULL DEFAULT 0,
            fetched_at  DATETIME     NULL,
            source      VARCHAR(64)  NOT NULL DEFAULT 'maxmind',
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        INSERT INTO geoip_db_meta (id) VALUES (1);
    END IF;
END;
CALL hpg_mig81_up();
DROP PROCEDURE hpg_mig81_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig81_down;
CREATE PROCEDURE hpg_mig81_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='geoip_db_meta') THEN
        DROP TABLE geoip_db_meta;
    END IF;
END;
CALL hpg_mig81_down();
DROP PROCEDURE hpg_mig81_down;
-- +goose StatementEnd
