-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig88_up;
CREATE PROCEDURE hpg_mig88_up()
BEGIN
    -- saved_filters: per-user named filter sets for list views.
    -- query_json stores the raw URL query string the user saved.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='saved_filters') THEN
        CREATE TABLE saved_filters (
            id         BIGINT       NOT NULL AUTO_INCREMENT,
            user_id    BIGINT       NOT NULL,
            view_key   VARCHAR(64)  NOT NULL,
            name       VARCHAR(120) NOT NULL,
            query_json TEXT         NOT NULL,
            created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            INDEX idx_sf_user_view (user_id, view_key),
            CONSTRAINT fk_sf_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    END IF;
END;
CALL hpg_mig88_up();
DROP PROCEDURE IF EXISTS hpg_mig88_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig88_down;
CREATE PROCEDURE hpg_mig88_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='saved_filters') THEN
        DROP TABLE saved_filters;
    END IF;
END;
CALL hpg_mig88_down();
DROP PROCEDURE IF EXISTS hpg_mig88_down;
-- +goose StatementEnd
