-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig33_up;
CREATE PROCEDURE hpg_mig33_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_via_wg_peer_id') THEN
        ALTER TABLE routes ADD COLUMN sso_via_wg_peer_id BIGINT UNSIGNED NULL AFTER sso_hosts;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_route_sso_wgpeer') THEN
        ALTER TABLE routes ADD CONSTRAINT fk_route_sso_wgpeer FOREIGN KEY (sso_via_wg_peer_id) REFERENCES customer_wg_peer(id) ON DELETE SET NULL;
    END IF;
END;
CALL hpg_mig33_up();
DROP PROCEDURE hpg_mig33_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig33_down;
CREATE PROCEDURE hpg_mig33_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_route_sso_wgpeer') THEN
        ALTER TABLE routes DROP FOREIGN KEY fk_route_sso_wgpeer;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='sso_via_wg_peer_id') THEN
        ALTER TABLE routes DROP COLUMN sso_via_wg_peer_id;
    END IF;
END;
CALL hpg_mig33_down();
DROP PROCEDURE hpg_mig33_down;
-- +goose StatementEnd
