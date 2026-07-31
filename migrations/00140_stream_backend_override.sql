-- +goose Up
-- +goose StatementBegin
-- A quarantined stream can only be released by fixing its destination, but the
-- backend lived on the shared services row and was not editable per stream.
DROP PROCEDURE IF EXISTS hpg_mig140_up;
CREATE PROCEDURE hpg_mig140_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='stream_routes' AND COLUMN_NAME='backend_ip_override') THEN
        ALTER TABLE stream_routes ADD COLUMN backend_ip_override VARCHAR(255) NULL;
    END IF;
END;
CALL hpg_mig140_up();
DROP PROCEDURE IF EXISTS hpg_mig140_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig140_down;
CREATE PROCEDURE hpg_mig140_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='stream_routes' AND COLUMN_NAME='backend_ip_override') THEN
        ALTER TABLE stream_routes DROP COLUMN backend_ip_override;
    END IF;
END;
CALL hpg_mig140_down();
DROP PROCEDURE IF EXISTS hpg_mig140_down;
-- +goose StatementEnd
