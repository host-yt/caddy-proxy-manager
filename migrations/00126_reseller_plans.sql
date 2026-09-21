-- +goose Up
-- Reseller v2 F1: reseller packages (aggregate quota + resource grants) and the
-- per-reseller identity/policy columns. A reseller subscribes to ONE
-- reseller_plan (Plesk "reseller plan" / WHM "account limits"); overselling and
-- plan-authoring are per-reseller policy flags (super_admin sets them), not part
-- of the shared package. Backfill gives every existing reseller an "Unlimited"
-- package so behaviour is unchanged. Columns avoid *_key/*_index length types to
-- dodge the MySQL->SQLite inline-index trap; new-table FKs are INLINE because
-- SQLite rejects adding FK constraints on an existing table, so the resellers
-- columns below carry no separately-added FK (app enforces integrity there).
--
-- HPG-015: this is the migration right after 00124 - the one an in-flight
-- upgrade is most likely to be interrupted on - so it gets the same guard
-- treatment: every DDL step below checks information_schema before acting,
-- and a guard that finds the object already present also verifies its shape,
-- SIGNALing (hard error) on a mismatch instead of silently building on top of
-- it. Seed INSERTs use INSERT IGNORE against the tables' own unique keys, and
-- the backfill UPDATEs already only touch NULL rows, so both are naturally
-- idempotent too.
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig126_up;
CREATE PROCEDURE hpg_mig126_up()
BEGIN
    -- max_* / rate_limit_rpm_cap: 0 means unlimited/uncapped.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='reseller_plans') THEN
        CREATE TABLE reseller_plans (
          id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
          name               VARCHAR(128) NOT NULL,
          max_clients        INT NOT NULL DEFAULT 0,
          max_domains_total  INT NOT NULL DEFAULT 0,
          max_services_total INT NOT NULL DEFAULT 0,
          rate_limit_rpm_cap INT NOT NULL DEFAULT 0,
          created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          UNIQUE KEY uq_reseller_plan_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ELSEIF (SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='reseller_plans'
               AND COLUMN_NAME IN ('id','name','max_clients','max_domains_total',
                                    'max_services_total','rate_limit_rpm_cap','created_at')) <> 7 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: reseller_plans table exists with an unexpected shape - manual repair required';
    END IF;

    -- Node pools a reseller package may place services on. Empty set = no pools.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='reseller_plan_node_groups') THEN
        CREATE TABLE reseller_plan_node_groups (
          reseller_plan_id BIGINT UNSIGNED NOT NULL,
          node_group_id    BIGINT UNSIGNED NOT NULL,
          PRIMARY KEY (reseller_plan_id, node_group_id),
          CONSTRAINT fk_rpng_plan FOREIGN KEY (reseller_plan_id) REFERENCES reseller_plans(id) ON DELETE CASCADE,
          CONSTRAINT fk_rpng_ng   FOREIGN KEY (node_group_id)    REFERENCES node_groups(id)    ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ELSEIF (SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='reseller_plan_node_groups'
               AND COLUMN_NAME IN ('reseller_plan_id','node_group_id')) <> 2 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: reseller_plan_node_groups table exists with an unexpected shape - manual repair required';
    END IF;

    -- Feature flags a reseller package grants (ssl, wildcard, websocket, path,
    -- external, waf, geo, l4, cache, rate_limit, dns01, weighted_lb). A reseller's
    -- own service plans may only enable features present here.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='reseller_plan_features') THEN
        CREATE TABLE reseller_plan_features (
          reseller_plan_id BIGINT UNSIGNED NOT NULL,
          feature          VARCHAR(32) NOT NULL,
          PRIMARY KEY (reseller_plan_id, feature),
          CONSTRAINT fk_rpf_plan FOREIGN KEY (reseller_plan_id) REFERENCES reseller_plans(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ELSEIF (SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='reseller_plan_features'
               AND COLUMN_NAME IN ('reseller_plan_id','feature')) <> 2 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: reseller_plan_features table exists with an unexpected shape - manual repair required';
    END IF;

    -- Per-reseller identity + policy (no ALTER-added FK: SQLite-safe, app enforces).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='reseller_plan_id') THEN
        ALTER TABLE resellers ADD COLUMN reseller_plan_id BIGINT UNSIGNED NULL;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='reseller_plan_id') <> 'bigint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: resellers.reseller_plan_id exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='owner_user_id') THEN
        ALTER TABLE resellers ADD COLUMN owner_user_id BIGINT UNSIGNED NULL;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='owner_user_id') <> 'bigint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: resellers.owner_user_id exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='overselling_allowed') THEN
        ALTER TABLE resellers ADD COLUMN overselling_allowed TINYINT(1) NOT NULL DEFAULT 0;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='overselling_allowed') <> 'tinyint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: resellers.overselling_allowed exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='can_create_plans') THEN
        ALTER TABLE resellers ADD COLUMN can_create_plans TINYINT(1) NOT NULL DEFAULT 0;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='can_create_plans') <> 'tinyint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00126: resellers.can_create_plans exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND INDEX_NAME='idx_resellers_plan') THEN
        ALTER TABLE resellers ADD KEY idx_resellers_plan (reseller_plan_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND INDEX_NAME='idx_resellers_owner') THEN
        ALTER TABLE resellers ADD KEY idx_resellers_owner (owner_user_id);
    END IF;

    -- Add the explicit 'reseller' role VALUE now (harmless), but do NOT promote
    -- existing reseller-admins yet: guards still key off users.reseller_id, so the
    -- role flip + guard rewrite happen together in F2. MODIFY is skipped on SQLite
    -- (role is TEXT there and already accepts any value). COLUMN_TYPE check doubles
    -- as the idempotency guard: MODIFY is naturally re-runnable, but skipping when
    -- the enum already carries 'reseller' avoids a pointless table rebuild.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='role'
                      AND COLUMN_TYPE LIKE '%reseller%') THEN
        ALTER TABLE users MODIFY COLUMN role ENUM('super_admin','admin','support','client','api','reseller') NOT NULL;
    END IF;
END;
CALL hpg_mig126_up();
DROP PROCEDURE IF EXISTS hpg_mig126_up;
-- +goose StatementEnd

-- Seed the "Unlimited" package (behaviour-neutral default for existing resellers).
-- IGNORE against uq_reseller_plan_name makes a re-run a no-op, never a duplicate.
-- +goose StatementBegin
INSERT IGNORE INTO reseller_plans (name, max_clients, max_domains_total, max_services_total, rate_limit_rpm_cap)
VALUES ('Unlimited', 0, 0, 0, 0);
-- +goose StatementEnd
-- +goose StatementBegin
-- Grant every node pool to Unlimited. IGNORE against the composite PK dodges duplicates on re-run.
INSERT IGNORE INTO reseller_plan_node_groups (reseller_plan_id, node_group_id)
SELECT rp.id, ng.id FROM reseller_plans rp CROSS JOIN node_groups ng WHERE rp.name = 'Unlimited';
-- +goose StatementEnd
-- +goose StatementBegin
-- Grant every feature to Unlimited. IGNORE against the composite PK dodges duplicates on re-run.
INSERT IGNORE INTO reseller_plan_features (reseller_plan_id, feature)
SELECT rp.id, f.feature FROM reseller_plans rp
JOIN (
  SELECT 'ssl' AS feature UNION ALL SELECT 'wildcard' UNION ALL SELECT 'websocket'
  UNION ALL SELECT 'path' UNION ALL SELECT 'external' UNION ALL SELECT 'waf'
  UNION ALL SELECT 'geo' UNION ALL SELECT 'l4' UNION ALL SELECT 'cache'
  UNION ALL SELECT 'rate_limit' UNION ALL SELECT 'dns01' UNION ALL SELECT 'weighted_lb'
) f
WHERE rp.name = 'Unlimited';
-- +goose StatementEnd

-- Backfill: existing resellers subscribe to Unlimited. Already idempotent: only
-- touches rows still NULL, so a re-run is a no-op.
-- +goose StatementBegin
UPDATE resellers SET reseller_plan_id = (SELECT id FROM reseller_plans WHERE name = 'Unlimited')
WHERE reseller_plan_id IS NULL;
-- +goose StatementEnd
-- +goose StatementBegin
-- Owner = the earliest user linked to the reseller (if any). Already idempotent (NULL-only).
UPDATE resellers SET owner_user_id = (SELECT MIN(u.id) FROM users u WHERE u.reseller_id = resellers.id)
WHERE owner_user_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig126_down;
CREATE PROCEDURE hpg_mig126_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='role'
                  AND COLUMN_TYPE LIKE '%reseller%') THEN
        ALTER TABLE users MODIFY COLUMN role ENUM('super_admin','admin','support','client','api') NOT NULL;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='can_create_plans') THEN
        ALTER TABLE resellers DROP COLUMN can_create_plans;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='overselling_allowed') THEN
        ALTER TABLE resellers DROP COLUMN overselling_allowed;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='owner_user_id') THEN
        ALTER TABLE resellers DROP COLUMN owner_user_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers' AND COLUMN_NAME='reseller_plan_id') THEN
        ALTER TABLE resellers DROP COLUMN reseller_plan_id;
    END IF;

    DROP TABLE IF EXISTS reseller_plan_features;
    DROP TABLE IF EXISTS reseller_plan_node_groups;
    DROP TABLE IF EXISTS reseller_plans;
END;
CALL hpg_mig126_down();
DROP PROCEDURE IF EXISTS hpg_mig126_down;
-- +goose StatementEnd
