-- +goose Up
-- +goose StatementBegin
-- Balancer CIDRs allowed to send an inbound PROXY header on a stream; without
-- it any client could claim an arbitrary source and bypass the CIDR ACL.
DROP PROCEDURE IF EXISTS hpg_mig174_up;
CREATE PROCEDURE hpg_mig174_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='stream_routes' AND COLUMN_NAME='proxy_proto_trusted') THEN
        ALTER TABLE stream_routes ADD COLUMN proxy_proto_trusted TEXT NULL;
    END IF;
END;
CALL hpg_mig174_up();
DROP PROCEDURE IF EXISTS hpg_mig174_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig174_down;
CREATE PROCEDURE hpg_mig174_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='stream_routes' AND COLUMN_NAME='proxy_proto_trusted') THEN
        ALTER TABLE stream_routes DROP COLUMN proxy_proto_trusted;
    END IF;
END;
CALL hpg_mig174_down();
DROP PROCEDURE IF EXISTS hpg_mig174_down;
-- +goose StatementEnd
