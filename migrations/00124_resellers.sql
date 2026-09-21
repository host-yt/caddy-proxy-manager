-- +goose Up
-- +goose StatementBegin
-- Reseller layer (Phase 1: schema only). A reseller owns a set of clients (and
-- optionally its own plans + branding) and is managed by a reseller-admin user
-- who sees ONLY that reseller's clients, never platform-global infra or other
-- resellers. reseller_id is NULL on every existing row (platform-direct), so this
-- migration is behavior-neutral until the scoping phase wires it. Columns named
-- reseller_id (not *_key/*_index) to dodge the MySQL->SQLite inline-index trap.
--
-- HPG-015: every step below is guarded, not just the CREATE TABLE. MariaDB/
-- MySQL DDL implicit-commits, so the original unguarded version could be
-- left partially applied by an interrupted run (e.g. `resellers` created but
-- the ALTERs on clients/plans/users never reached); a bare retry then failed
-- on "table already exists" and halted every later migration. A guard that
-- only checks existence can't tell a same-named leftover from a prior good
-- run apart from a wrong-shaped object left by something else entirely, so
-- each guard also checks the object's shape and SIGNALs (hard error, not a
-- silent skip) if it doesn't match - an operator must look at that by hand,
-- never have it papered over.
DROP PROCEDURE IF EXISTS hpg_mig124_up;
CREATE PROCEDURE hpg_mig124_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers') THEN
        CREATE TABLE resellers (
          id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          name          VARCHAR(120) NOT NULL,
          slug          VARCHAR(64)  NOT NULL,
          status        ENUM('active','suspended') NOT NULL DEFAULT 'active',
          brand_name    VARCHAR(120) NULL,
          logo_url      VARCHAR(512) NULL,
          support_email VARCHAR(255) NULL,
          primary_color VARCHAR(16)  NULL,
          created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uq_reseller_slug (slug)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ELSEIF (SELECT COUNT(*) FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='resellers'
               AND COLUMN_NAME IN ('id','name','slug','status','brand_name',
                                    'logo_url','support_email','primary_color',
                                    'created_at','updated_at')) <> 10 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00124: resellers table exists with an unexpected shape - manual repair required';
    END IF;

    -- Ownership: NULL = platform-direct (super-admin owned). ON DELETE SET NULL so
    -- removing a reseller returns its clients to platform-direct, never cascading a
    -- delete of customer data.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='reseller_id') THEN
        ALTER TABLE clients ADD COLUMN reseller_id BIGINT UNSIGNED NULL;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='reseller_id') <> 'bigint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00124: clients.reseller_id exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND INDEX_NAME='idx_clients_reseller') THEN
        ALTER TABLE clients ADD KEY idx_clients_reseller (reseller_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
                      AND CONSTRAINT_NAME='fk_clients_reseller' AND CONSTRAINT_TYPE='FOREIGN KEY') THEN
        ALTER TABLE clients ADD CONSTRAINT fk_clients_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL;
    END IF;

    -- Reseller-specific plans: NULL = global plan available to every tenant.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='reseller_id') THEN
        ALTER TABLE plans ADD COLUMN reseller_id BIGINT UNSIGNED NULL;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='reseller_id') <> 'bigint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00124: plans.reseller_id exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND INDEX_NAME='idx_plans_reseller') THEN
        ALTER TABLE plans ADD KEY idx_plans_reseller (reseller_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans'
                      AND CONSTRAINT_NAME='fk_plans_reseller' AND CONSTRAINT_TYPE='FOREIGN KEY') THEN
        ALTER TABLE plans ADD CONSTRAINT fk_plans_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL;
    END IF;

    -- Reseller-admin linkage: a user with role 'admin' AND reseller_id set is a
    -- reseller-admin scoped to that reseller's clients (enforced in the scoping phase).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='reseller_id') THEN
        ALTER TABLE users ADD COLUMN reseller_id BIGINT UNSIGNED NULL;
    ELSEIF (SELECT DATA_TYPE FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='reseller_id') <> 'bigint' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT =
            'migration 00124: users.reseller_id exists with an unexpected type - manual repair required';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.STATISTICS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND INDEX_NAME='idx_users_reseller') THEN
        ALTER TABLE users ADD KEY idx_users_reseller (reseller_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'
                      AND CONSTRAINT_NAME='fk_users_reseller' AND CONSTRAINT_TYPE='FOREIGN KEY') THEN
        ALTER TABLE users ADD CONSTRAINT fk_users_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL;
    END IF;
END;
CALL hpg_mig124_up();
DROP PROCEDURE IF EXISTS hpg_mig124_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig124_down;
CREATE PROCEDURE hpg_mig124_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'
                  AND CONSTRAINT_NAME='fk_users_reseller' AND CONSTRAINT_TYPE='FOREIGN KEY') THEN
        ALTER TABLE users DROP FOREIGN KEY fk_users_reseller;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='reseller_id') THEN
        ALTER TABLE users DROP COLUMN reseller_id;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans'
                  AND CONSTRAINT_NAME='fk_plans_reseller' AND CONSTRAINT_TYPE='FOREIGN KEY') THEN
        ALTER TABLE plans DROP FOREIGN KEY fk_plans_reseller;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='plans' AND COLUMN_NAME='reseller_id') THEN
        ALTER TABLE plans DROP COLUMN reseller_id;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients'
                  AND CONSTRAINT_NAME='fk_clients_reseller' AND CONSTRAINT_TYPE='FOREIGN KEY') THEN
        ALTER TABLE clients DROP FOREIGN KEY fk_clients_reseller;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='clients' AND COLUMN_NAME='reseller_id') THEN
        ALTER TABLE clients DROP COLUMN reseller_id;
    END IF;

    DROP TABLE IF EXISTS resellers;
END;
CALL hpg_mig124_down();
DROP PROCEDURE IF EXISTS hpg_mig124_down;
-- +goose StatementEnd
