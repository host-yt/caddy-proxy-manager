-- +goose Up
-- +goose StatementBegin
-- Reseller layer (Phase 1: schema only). A reseller owns a set of clients (and
-- optionally its own plans + branding) and is managed by a reseller-admin user
-- who sees ONLY that reseller's clients, never platform-global infra or other
-- resellers. reseller_id is NULL on every existing row (platform-direct), so this
-- migration is behavior-neutral until the scoping phase wires it. Columns named
-- reseller_id (not *_key/*_index) to dodge the MySQL->SQLite inline-index trap.
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
-- +goose StatementEnd

-- +goose StatementBegin
-- Ownership: NULL = platform-direct (super-admin owned). ON DELETE SET NULL so
-- removing a reseller returns its clients to platform-direct, never cascading a
-- delete of customer data.
ALTER TABLE clients ADD COLUMN reseller_id BIGINT UNSIGNED NULL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE clients ADD KEY idx_clients_reseller (reseller_id);
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE clients ADD CONSTRAINT fk_clients_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL;
-- +goose StatementEnd

-- +goose StatementBegin
-- Reseller-specific plans: NULL = global plan available to every tenant.
ALTER TABLE plans ADD COLUMN reseller_id BIGINT UNSIGNED NULL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE plans ADD KEY idx_plans_reseller (reseller_id);
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE plans ADD CONSTRAINT fk_plans_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL;
-- +goose StatementEnd

-- +goose StatementBegin
-- Reseller-admin linkage: a user with role 'admin' AND reseller_id set is a
-- reseller-admin scoped to that reseller's clients (enforced in the scoping phase).
ALTER TABLE users ADD COLUMN reseller_id BIGINT UNSIGNED NULL;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE users ADD KEY idx_users_reseller (reseller_id);
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE users ADD CONSTRAINT fk_users_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP FOREIGN KEY fk_users_reseller;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN reseller_id;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE plans DROP FOREIGN KEY fk_plans_reseller;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE plans DROP COLUMN reseller_id;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE clients DROP FOREIGN KEY fk_clients_reseller;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE clients DROP COLUMN reseller_id;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS resellers;
-- +goose StatementEnd
