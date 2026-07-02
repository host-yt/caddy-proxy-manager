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

-- +goose StatementBegin
-- max_* / rate_limit_rpm_cap: 0 means unlimited/uncapped.
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
-- +goose StatementEnd

-- +goose StatementBegin
-- Node pools a reseller package may place services on. Empty set = no pools.
CREATE TABLE reseller_plan_node_groups (
  reseller_plan_id BIGINT UNSIGNED NOT NULL,
  node_group_id    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (reseller_plan_id, node_group_id),
  CONSTRAINT fk_rpng_plan FOREIGN KEY (reseller_plan_id) REFERENCES reseller_plans(id) ON DELETE CASCADE,
  CONSTRAINT fk_rpng_ng   FOREIGN KEY (node_group_id)    REFERENCES node_groups(id)    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Feature flags a reseller package grants (ssl, wildcard, websocket, path,
-- external, waf, geo, l4, cache, rate_limit, dns01, weighted_lb). A reseller's
-- own service plans may only enable features present here.
CREATE TABLE reseller_plan_features (
  reseller_plan_id BIGINT UNSIGNED NOT NULL,
  feature          VARCHAR(32) NOT NULL,
  PRIMARY KEY (reseller_plan_id, feature),
  CONSTRAINT fk_rpf_plan FOREIGN KEY (reseller_plan_id) REFERENCES reseller_plans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- Per-reseller identity + policy (no ALTER-added FK: SQLite-safe, app enforces).
-- +goose StatementBegin
ALTER TABLE resellers ADD COLUMN reseller_plan_id BIGINT UNSIGNED NULL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers ADD COLUMN owner_user_id BIGINT UNSIGNED NULL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers ADD COLUMN overselling_allowed TINYINT(1) NOT NULL DEFAULT 0;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers ADD COLUMN can_create_plans TINYINT(1) NOT NULL DEFAULT 0;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers ADD KEY idx_resellers_plan (reseller_plan_id);
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers ADD KEY idx_resellers_owner (owner_user_id);
-- +goose StatementEnd

-- Add the explicit 'reseller' role VALUE now (harmless), but do NOT promote
-- existing reseller-admins yet: guards still key off users.reseller_id, so the
-- role flip + guard rewrite happen together in F2. MODIFY is skipped on SQLite
-- (role is TEXT there and already accepts any value).
-- +goose StatementBegin
ALTER TABLE users MODIFY COLUMN role ENUM('super_admin','admin','support','client','api','reseller') NOT NULL;
-- +goose StatementEnd

-- Seed the "Unlimited" package (behaviour-neutral default for existing resellers).
-- +goose StatementBegin
INSERT INTO reseller_plans (name, max_clients, max_domains_total, max_services_total, rate_limit_rpm_cap)
VALUES ('Unlimited', 0, 0, 0, 0);
-- +goose StatementEnd
-- +goose StatementBegin
-- Grant every node pool to Unlimited.
INSERT INTO reseller_plan_node_groups (reseller_plan_id, node_group_id)
SELECT rp.id, ng.id FROM reseller_plans rp CROSS JOIN node_groups ng WHERE rp.name = 'Unlimited';
-- +goose StatementEnd
-- +goose StatementBegin
-- Grant every feature to Unlimited.
INSERT INTO reseller_plan_features (reseller_plan_id, feature)
SELECT rp.id, f.feature FROM reseller_plans rp
JOIN (
  SELECT 'ssl' AS feature UNION ALL SELECT 'wildcard' UNION ALL SELECT 'websocket'
  UNION ALL SELECT 'path' UNION ALL SELECT 'external' UNION ALL SELECT 'waf'
  UNION ALL SELECT 'geo' UNION ALL SELECT 'l4' UNION ALL SELECT 'cache'
  UNION ALL SELECT 'rate_limit' UNION ALL SELECT 'dns01' UNION ALL SELECT 'weighted_lb'
) f
WHERE rp.name = 'Unlimited';
-- +goose StatementEnd

-- Backfill: existing resellers subscribe to Unlimited.
-- +goose StatementBegin
UPDATE resellers SET reseller_plan_id = (SELECT id FROM reseller_plans WHERE name = 'Unlimited')
WHERE reseller_plan_id IS NULL;
-- +goose StatementEnd
-- +goose StatementBegin
-- Owner = the earliest user linked to the reseller (if any).
UPDATE resellers SET owner_user_id = (SELECT MIN(u.id) FROM users u WHERE u.reseller_id = resellers.id)
WHERE owner_user_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users MODIFY COLUMN role ENUM('super_admin','admin','support','client','api') NOT NULL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers DROP COLUMN can_create_plans;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers DROP COLUMN overselling_allowed;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers DROP COLUMN owner_user_id;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE resellers DROP COLUMN reseller_plan_id;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS reseller_plan_features;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS reseller_plan_node_groups;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS reseller_plans;
-- +goose StatementEnd
