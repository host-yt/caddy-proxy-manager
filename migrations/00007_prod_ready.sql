-- +goose Up
-- +goose StatementBegin
-- Webhook endpoints + delivery log.
CREATE TABLE webhook_endpoints (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(128) NOT NULL,
  url          VARCHAR(512) NOT NULL,
  secret_enc   TEXT,                          -- HMAC signing secret (AES-GCM)
  events       VARCHAR(512) NOT NULL,         -- comma-separated event types
  is_enabled   TINYINT(1) NOT NULL DEFAULT 1,
  created_by   BIGINT UNSIGNED NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_wh_name (name),
  KEY idx_wh_enabled (is_enabled),
  CONSTRAINT fk_wh_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE webhook_deliveries (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  endpoint_id  BIGINT UNSIGNED NOT NULL,
  event_type   VARCHAR(64) NOT NULL,
  payload      JSON NOT NULL,
  status       ENUM('pending','success','failed') NOT NULL DEFAULT 'pending',
  http_code    INT,
  attempts     INT NOT NULL DEFAULT 0,
  last_error   TEXT,
  next_retry_at TIMESTAMP NULL,
  delivered_at TIMESTAMP NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_wd_endpoint (endpoint_id),
  KEY idx_wd_status_retry (status, next_retry_at),
  CONSTRAINT fk_wd_endpoint FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Customer-visible documents (ToS, privacy policy, custom welcome).
CREATE TABLE legal_documents (
  slug         VARCHAR(64) PRIMARY KEY,
  title        VARCHAR(255) NOT NULL,
  body         MEDIUMTEXT NOT NULL,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
  updated_by   BIGINT UNSIGNED NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- GDPR data-deletion log (cannot reverse the deletion; keep an audit of who/what).
CREATE TABLE data_deletions (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id      BIGINT UNSIGNED NOT NULL,
  email        VARCHAR(255) NOT NULL,
  requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  requested_by BIGINT UNSIGNED NULL,
  completed_at TIMESTAMP NULL,
  KEY idx_dd_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- node_groups.mode = active_active needs runtime tracking which nodes the
-- route was actually pushed to (one row → N nodes). Keep the existing
-- routes.caddy_node_id as the "primary" slot; add a join table for fan-out.
CREATE TABLE route_node_assignments (
  route_id     BIGINT UNSIGNED NOT NULL,
  node_id      BIGINT UNSIGNED NOT NULL,
  last_pushed_at TIMESTAMP NULL,
  last_pushed_hash CHAR(64),
  PRIMARY KEY (route_id, node_id),
  KEY idx_rna_node (node_id),
  CONSTRAINT fk_rna_route FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
  CONSTRAINT fk_rna_node FOREIGN KEY (node_id) REFERENCES caddy_nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- API key per-key rate-limit (requests/min). NULL → no per-key limit.
ALTER TABLE api_keys
  ADD COLUMN rate_limit_rpm INT NULL AFTER scopes;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_keys DROP COLUMN rate_limit_rpm;
DROP TABLE IF EXISTS route_node_assignments;
DROP TABLE IF EXISTS data_deletions;
DROP TABLE IF EXISTS legal_documents;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;
-- +goose StatementEnd
