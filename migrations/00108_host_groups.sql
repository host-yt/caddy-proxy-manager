-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig108_up;
CREATE PROCEDURE hpg_mig108_up()
BEGIN
    -- Host groups: logical grouping for routes/hosts
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_groups') THEN
        CREATE TABLE host_groups (
            id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name       VARCHAR(128) NOT NULL,
            color      VARCHAR(7) NOT NULL DEFAULT '#6366f1',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_hg_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='group_id') THEN
        ALTER TABLE routes ADD COLUMN group_id BIGINT UNSIGNED NULL,
            ADD CONSTRAINT fk_route_group FOREIGN KEY (group_id) REFERENCES host_groups(id) ON DELETE SET NULL,
            ADD KEY idx_route_group (group_id);
    END IF;
END;
CALL hpg_mig108_up();
DROP PROCEDURE IF EXISTS hpg_mig108_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig108_down;
CREATE PROCEDURE hpg_mig108_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='group_id') THEN
        ALTER TABLE routes DROP FOREIGN KEY fk_route_group, DROP KEY idx_route_group, DROP COLUMN group_id;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.TABLES
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='host_groups') THEN
        DROP TABLE host_groups;
    END IF;
END;
CALL hpg_mig108_down();
DROP PROCEDURE IF EXISTS hpg_mig108_down;
-- +goose StatementEnd
