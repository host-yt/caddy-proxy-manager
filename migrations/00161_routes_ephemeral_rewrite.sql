-- +goose Up
-- +goose StatementBegin
-- Short-lived routes (expires_at, swept by the leader) and path rewrite for
-- external upstreams (strip our prefix, prepend the origin's base path).
DROP PROCEDURE IF EXISTS hpg_mig161_up;
CREATE PROCEDURE hpg_mig161_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='expires_at') THEN
        ALTER TABLE routes ADD COLUMN expires_at DATETIME NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='strip_path_prefix') THEN
        ALTER TABLE routes ADD COLUMN strip_path_prefix TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='upstream_path') THEN
        ALTER TABLE routes ADD COLUMN upstream_path VARCHAR(512) NULL;
    END IF;
END;
CALL hpg_mig161_up();
DROP PROCEDURE IF EXISTS hpg_mig161_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig161_down;
CREATE PROCEDURE hpg_mig161_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='expires_at') THEN
        ALTER TABLE routes DROP COLUMN expires_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='strip_path_prefix') THEN
        ALTER TABLE routes DROP COLUMN strip_path_prefix;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='upstream_path') THEN
        ALTER TABLE routes DROP COLUMN upstream_path;
    END IF;
END;
CALL hpg_mig161_down();
DROP PROCEDURE IF EXISTS hpg_mig161_down;
-- +goose StatementEnd
