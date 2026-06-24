-- +goose Up
-- +goose StatementBegin
-- ============================================================================
-- Hostyt Proxy Gateway - initial schema
-- ============================================================================

CREATE TABLE settings (
  `key`        VARCHAR(128) PRIMARY KEY,
  value        TEXT NOT NULL,
  is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                          ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE users (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email           VARCHAR(255) NOT NULL,
  password_hash   VARCHAR(255) NOT NULL,
  role            ENUM('super_admin','admin','support','client','api') NOT NULL,
  full_name       VARCHAR(255),
  is_active       TINYINT(1) NOT NULL DEFAULT 1,
  totp_secret     VARBINARY(255),
  totp_enabled    TINYINT(1) NOT NULL DEFAULT 0,
  oidc_subject    VARCHAR(255),
  oidc_issuer     VARCHAR(255),
  last_login_at   TIMESTAMP NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_email (email),
  KEY idx_users_role (role),
  KEY idx_users_oidc (oidc_issuer, oidc_subject)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE recovery_codes (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id       BIGINT UNSIGNED NOT NULL,
  code_hash     VARCHAR(255) NOT NULL,
  used_at       TIMESTAMP NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_rc_user (user_id),
  CONSTRAINT fk_rc_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE api_keys (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(128) NOT NULL,
  key_prefix   CHAR(8) NOT NULL,
  key_hash     VARCHAR(255) NOT NULL,
  scopes       VARCHAR(512) NOT NULL DEFAULT '',
  last_used_at TIMESTAMP NULL,
  revoked_at   TIMESTAMP NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_ak_user (user_id),
  KEY idx_ak_prefix (key_prefix),
  CONSTRAINT fk_ak_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE clients (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id         BIGINT UNSIGNED NOT NULL,
  display_name    VARCHAR(255),
  external_ref    VARCHAR(128),
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_clients_user (user_id),
  KEY idx_clients_ext (external_ref),
  CONSTRAINT fk_clients_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE node_groups (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(128) NOT NULL,
  mode         ENUM('single','active_active','failover') NOT NULL DEFAULT 'single',
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_ng_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE caddy_nodes (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name             VARCHAR(128) NOT NULL,
  api_url          VARCHAR(255) NOT NULL,
  public_hostname  VARCHAR(255),
  public_ip        VARCHAR(45),
  node_group_id    BIGINT UNSIGNED NOT NULL,
  max_routes       INT NOT NULL DEFAULT 1000,
  current_routes   INT NOT NULL DEFAULT 0,
  priority         INT NOT NULL DEFAULT 100,
  is_enabled       TINYINT(1) NOT NULL DEFAULT 1,
  health_status    ENUM('unknown','healthy','degraded','down') NOT NULL DEFAULT 'unknown',
  last_seen_at     TIMESTAMP NULL,
  notes            TEXT,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_node_name (name),
  KEY idx_node_group (node_group_id),
  CONSTRAINT fk_node_group FOREIGN KEY (node_group_id) REFERENCES node_groups(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE plans (
  id                    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name                  VARCHAR(128) NOT NULL,
  max_domains           INT NOT NULL DEFAULT 5,
  max_ports             INT NOT NULL DEFAULT 20,
  ssl_enabled           TINYINT(1) NOT NULL DEFAULT 1,
  path_routing_enabled  TINYINT(1) NOT NULL DEFAULT 0,
  wildcard_enabled      TINYINT(1) NOT NULL DEFAULT 0,
  websocket_enabled     TINYINT(1) NOT NULL DEFAULT 1,
  rate_limit_rpm        INT,
  node_group_id         BIGINT UNSIGNED NOT NULL,
  created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_plan_name (name),
  KEY idx_plan_ng (node_group_id),
  CONSTRAINT fk_plan_ng FOREIGN KEY (node_group_id) REFERENCES node_groups(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE services (
  id                    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  client_id             BIGINT UNSIGNED NOT NULL,
  name                  VARCHAR(128) NOT NULL,
  backend_ip            VARCHAR(45) NOT NULL,           -- admin-only
  allowed_port_start    INT NOT NULL,                   -- admin-only
  allowed_port_end      INT NOT NULL,                   -- admin-only
  plan_id               BIGINT UNSIGNED NOT NULL,
  node_group_id         BIGINT UNSIGNED NOT NULL,
  status                ENUM('active','suspended','terminated') NOT NULL DEFAULT 'active',
  external_reference    VARCHAR(128),
  notes                 TEXT,
  created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                                   ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_svc_client (client_id),
  KEY idx_svc_ext (external_reference),
  CONSTRAINT fk_svc_client FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
  CONSTRAINT fk_svc_plan   FOREIGN KEY (plan_id) REFERENCES plans(id),
  CONSTRAINT fk_svc_ng     FOREIGN KEY (node_group_id) REFERENCES node_groups(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE routes (
  id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  service_id        BIGINT UNSIGNED NOT NULL,
  caddy_node_id     BIGINT UNSIGNED NOT NULL,
  domain            VARCHAR(253) NOT NULL,
  path_prefix       VARCHAR(255) NOT NULL DEFAULT '',
  upstream_port     INT NOT NULL,
  ssl_enabled       TINYINT(1) NOT NULL DEFAULT 1,
  websocket         TINYINT(1) NOT NULL DEFAULT 1,
  force_https       TINYINT(1) NOT NULL DEFAULT 1,
  http2_enabled     TINYINT(1) NOT NULL DEFAULT 1,
  http3_enabled     TINYINT(1) NOT NULL DEFAULT 0,
  status            ENUM('pending_dns','dns_ok','pending_ssl','active','failed','disabled')
                       NOT NULL DEFAULT 'pending_dns',
  last_error        TEXT,
  dns_checked_at    TIMESTAMP NULL,
  ssl_issued_at     TIMESTAMP NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                               ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_route_domain_path (domain, path_prefix),
  KEY idx_route_domain (domain),                -- hot path for /internal/ask
  KEY idx_route_service (service_id),
  KEY idx_route_status (status),
  CONSTRAINT fk_route_svc FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
  CONSTRAINT fk_route_node FOREIGN KEY (caddy_node_id) REFERENCES caddy_nodes(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE audit_log (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     BIGINT UNSIGNED NULL,
  actor_type  ENUM('user','api','system') NOT NULL,
  action      VARCHAR(128) NOT NULL,
  entity      VARCHAR(64) NOT NULL,
  entity_id   VARCHAR(64),
  ip          VARCHAR(45),
  user_agent  VARCHAR(255),
  meta        JSON,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_user (user_id),
  KEY idx_audit_entity (entity, entity_id),
  KEY idx_audit_action (action),
  KEY idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS routes;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS plans;
DROP TABLE IF EXISTS caddy_nodes;
DROP TABLE IF EXISTS node_groups;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS settings;
-- +goose StatementEnd
