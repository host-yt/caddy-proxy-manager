-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig22_up;
CREATE PROCEDURE hpg_mig22_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='peer_group_id') THEN
        ALTER TABLE customer_wg_peer ADD COLUMN peer_group_id CHAR(36) NULL AFTER name;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND INDEX_NAME='idx_peer_group') THEN
        ALTER TABLE customer_wg_peer ADD KEY idx_peer_group (peer_group_id);
    END IF;
END;
CALL hpg_mig22_up();
DROP PROCEDURE hpg_mig22_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig22_down;
CREATE PROCEDURE hpg_mig22_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND INDEX_NAME='idx_peer_group') THEN
        ALTER TABLE customer_wg_peer DROP KEY idx_peer_group;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='customer_wg_peer' AND COLUMN_NAME='peer_group_id') THEN
        ALTER TABLE customer_wg_peer DROP COLUMN peer_group_id;
    END IF;
END;
CALL hpg_mig22_down();
DROP PROCEDURE hpg_mig22_down;
-- +goose StatementEnd
