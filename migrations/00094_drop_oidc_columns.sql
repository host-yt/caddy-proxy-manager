-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig94_up;
CREATE PROCEDURE hpg_mig94_up()
BEGIN
    -- oauth_identities (mig84) is the sole source of truth for OIDC links, but
    -- mig84 never backfilled legacy users.oidc_subject/issuer into it. Copy any
    -- legacy link in BEFORE dropping the columns, else OIDC users who have not
    -- logged in since mig84 lose their only link and can no longer sign in.
    -- (provider,issuer,subject) must match the live OIDC lookup in auth.go exactly.
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='oidc_subject') THEN
        INSERT INTO oauth_identities (user_id, provider, subject, email, issuer)
        SELECT u.id, 'oidc', u.oidc_subject, NULLIF(u.email, ''), COALESCE(u.oidc_issuer, '')
        FROM users u
        WHERE u.oidc_subject IS NOT NULL AND u.oidc_subject <> ''
        ON DUPLICATE KEY UPDATE user_id = oauth_identities.user_id;
    END IF;

    -- Drop the now-redundant legacy columns from users.
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='oidc_subject') THEN
        ALTER TABLE users DROP COLUMN oidc_subject;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='oidc_issuer') THEN
        ALTER TABLE users DROP COLUMN oidc_issuer;
    END IF;
    -- Drop the index that covered both columns (only if it still exists).
    IF EXISTS (SELECT 1 FROM information_schema.STATISTICS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND INDEX_NAME='idx_users_oidc') THEN
        ALTER TABLE users DROP INDEX idx_users_oidc;
    END IF;
END;
CALL hpg_mig94_up();
DROP PROCEDURE IF EXISTS hpg_mig94_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig94_down;
CREATE PROCEDURE hpg_mig94_down()
BEGIN
    -- Restore nullable columns so the schema matches pre-mig94 state.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='oidc_subject') THEN
        ALTER TABLE users ADD COLUMN oidc_subject VARCHAR(255) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='oidc_issuer') THEN
        ALTER TABLE users ADD COLUMN oidc_issuer VARCHAR(255) NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND INDEX_NAME='idx_users_oidc') THEN
        ALTER TABLE users ADD KEY idx_users_oidc (oidc_issuer, oidc_subject);
    END IF;
END;
CALL hpg_mig94_down();
DROP PROCEDURE IF EXISTS hpg_mig94_down;
-- +goose StatementEnd
