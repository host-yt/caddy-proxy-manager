-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig78_up;
CREATE PROCEDURE hpg_mig78_up()
BEGIN
    -- Local access groups for the built-in forward-auth portal. Members are
    -- existing users (reuse users table + argon2 hashes); no parallel creds.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='access_groups') THEN
        CREATE TABLE access_groups (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            name        VARCHAR(128)    NOT NULL,
            description VARCHAR(255)    NOT NULL DEFAULT '',
            -- owning client: scopes group management to that client's admins.
            -- NULL = global group manageable only by super_admin.
            client_id   BIGINT UNSIGNED NULL,
            created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_ag_client_name (client_id, name),
            INDEX idx_ag_client (client_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='access_group_members') THEN
        CREATE TABLE access_group_members (
            group_id   BIGINT UNSIGNED NOT NULL,
            user_id    BIGINT UNSIGNED NOT NULL,
            created_at TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, user_id),
            INDEX idx_agm_user (user_id),
            CONSTRAINT fk_agm_group FOREIGN KEY (group_id) REFERENCES access_groups(id) ON DELETE CASCADE,
            CONSTRAINT fk_agm_user  FOREIGN KEY (user_id)  REFERENCES users(id)         ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    -- Which group(s) may access which route. A route with >=1 grant is
    -- protected by the built-in portal; empty = portal off for that route.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='route_access_grants') THEN
        CREATE TABLE route_access_grants (
            route_id   BIGINT UNSIGNED NOT NULL,
            group_id   BIGINT UNSIGNED NOT NULL,
            created_at TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (route_id, group_id),
            INDEX idx_rag_group (group_id),
            CONSTRAINT fk_rag_route FOREIGN KEY (route_id) REFERENCES routes(id)         ON DELETE CASCADE,
            CONSTRAINT fk_rag_group FOREIGN KEY (group_id) REFERENCES access_groups(id)  ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    -- Per-route toggle. The grant rows decide WHO; this flag lets an operator
    -- keep grants configured but momentarily disable the gate without losing them.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes'
                     AND COLUMN_NAME='portal_protect') THEN
        ALTER TABLE routes ADD COLUMN portal_protect TINYINT(1) NOT NULL DEFAULT 0;
    END IF;
END;
CALL hpg_mig78_up();
DROP PROCEDURE IF EXISTS hpg_mig78_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig78_down;
CREATE PROCEDURE hpg_mig78_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes'
                 AND COLUMN_NAME='portal_protect') THEN
        ALTER TABLE routes DROP COLUMN portal_protect;
    END IF;
END;
CALL hpg_mig78_down();
DROP PROCEDURE IF EXISTS hpg_mig78_down;

DROP TABLE IF EXISTS route_access_grants;
DROP TABLE IF EXISTS access_group_members;
DROP TABLE IF EXISTS access_groups;

-- +goose StatementEnd
