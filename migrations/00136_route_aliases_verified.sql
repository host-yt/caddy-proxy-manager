-- +goose Up
-- +goose StatementBegin
-- Aliases become host matchers and cert subjects just like the primary domain,
-- so each one needs its own ownership proof. This column records the proven
-- subset; anything outside it is neither emitted nor cert-eligible.
DROP PROCEDURE IF EXISTS hpg_mig136_up;
CREATE PROCEDURE hpg_mig136_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='aliases_verified') THEN
        ALTER TABLE routes ADD COLUMN aliases_verified TEXT NULL;
        -- Backfill: pre-existing aliases were named under the old trust model.
        -- Dropping them here would take live sites offline, which is not the
        -- risk this column addresses (that is newly added aliases).
        UPDATE routes SET aliases_verified = aliases WHERE aliases IS NOT NULL AND aliases <> '';
    END IF;
END;
CALL hpg_mig136_up();
DROP PROCEDURE IF EXISTS hpg_mig136_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig136_down;
CREATE PROCEDURE hpg_mig136_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='aliases_verified') THEN
        ALTER TABLE routes DROP COLUMN aliases_verified;
    END IF;
END;
CALL hpg_mig136_down();
DROP PROCEDURE IF EXISTS hpg_mig136_down;
-- +goose StatementEnd
