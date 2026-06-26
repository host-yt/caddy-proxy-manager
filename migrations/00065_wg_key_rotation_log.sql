-- +goose Up
-- +goose StatementBegin

-- Audit trail for every WG key rotation event, regardless of source.
-- Allows ops to see exactly when each peer was rotated and by whom.

DROP PROCEDURE IF EXISTS hpg_mig65_up;
CREATE PROCEDURE hpg_mig65_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='wg_key_rotation_log') THEN
        CREATE TABLE wg_key_rotation_log (
            id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            peer_id       BIGINT UNSIGNED NOT NULL,
            rotated_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            source        ENUM('manual','job','reissue') NOT NULL,
            actor_user_id BIGINT UNSIGNED NULL,
            note          VARCHAR(255)    NULL,
            PRIMARY KEY (id),
            INDEX idx_wkrl_peer_rotated (peer_id, rotated_at)
        );
    END IF;
END;
CALL hpg_mig65_up();
DROP PROCEDURE hpg_mig65_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig65_down;
CREATE PROCEDURE hpg_mig65_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLES
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='wg_key_rotation_log') THEN
        DROP TABLE wg_key_rotation_log;
    END IF;
END;
CALL hpg_mig65_down();
DROP PROCEDURE hpg_mig65_down;
-- +goose StatementEnd
