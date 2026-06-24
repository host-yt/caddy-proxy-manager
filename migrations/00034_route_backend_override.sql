-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig34_up;
CREATE PROCEDURE hpg_mig34_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='backend_ip_override') THEN
        ALTER TABLE routes ADD COLUMN backend_ip_override VARCHAR(255) NULL AFTER via_wg_peer_id;
    END IF;
END;
CALL hpg_mig34_up();
DROP PROCEDURE hpg_mig34_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig34_down;
CREATE PROCEDURE hpg_mig34_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='backend_ip_override') THEN
        ALTER TABLE routes DROP COLUMN backend_ip_override;
    END IF;
END;
CALL hpg_mig34_down();
DROP PROCEDURE hpg_mig34_down;
-- +goose StatementEnd
