-- +goose Up
-- +goose StatementBegin
-- Per-route acceptance that the backend hostname is resolved by the node, not
-- by the panel. A name the panel cannot resolve is otherwise refused: panel
-- resolution failing must not be read as "destination approved". 0 (default)
-- means the panel resolves, screens and pins the backend address itself.
DROP PROCEDURE IF EXISTS hpg_mig146_up;
CREATE PROCEDURE hpg_mig146_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='backend_resolve_node_side') THEN
        ALTER TABLE routes ADD COLUMN backend_resolve_node_side TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig146_up();
DROP PROCEDURE IF EXISTS hpg_mig146_up;
-- +goose StatementEnd

-- +goose StatementBegin
-- Grandfather tunnel-bound routes: their backend has always been resolved on
-- the node side, so upgrading must not take them down. Everything else keeps
-- the strict default and has to opt out deliberately.
UPDATE routes SET backend_resolve_node_side = 1 WHERE via_wg_peer_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig146_down;
CREATE PROCEDURE hpg_mig146_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='backend_resolve_node_side') THEN
        ALTER TABLE routes DROP COLUMN backend_resolve_node_side;
    END IF;
END;
CALL hpg_mig146_down();
DROP PROCEDURE IF EXISTS hpg_mig146_down;
-- +goose StatementEnd
