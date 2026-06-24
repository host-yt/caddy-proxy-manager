-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig37_up;
CREATE PROCEDURE hpg_mig37_up()
BEGIN
    -- Per-route opt-out of the stock `encode` handler (gzip/zstd).
    -- Default 0 = compression ON; set 1 when upstream already compresses.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='compress_disabled') THEN
        ALTER TABLE routes ADD COLUMN compress_disabled TINYINT(1) NOT NULL DEFAULT 0 AFTER proxy_secret_enc;
    END IF;
END;
CALL hpg_mig37_up();
DROP PROCEDURE hpg_mig37_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig37_down;
CREATE PROCEDURE hpg_mig37_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='compress_disabled') THEN
        ALTER TABLE routes DROP COLUMN compress_disabled;
    END IF;
END;
CALL hpg_mig37_down();
DROP PROCEDURE hpg_mig37_down;
-- +goose StatementEnd
