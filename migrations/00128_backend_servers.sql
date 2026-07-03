-- +goose Up
-- +goose StatementBegin
-- Backend-server registry: admins pick a known server instead of retyping raw
-- IPs on every service. reseller_id NULL = global/platform server visible to
-- everyone; set = owned by one reseller (reseller-admin sees only own + global).
-- New table so the FK is inline (SQLite rejects ALTER-added FKs on an existing
-- table); external_ref links to an external system (e.g. hosting panel) id.
CREATE TABLE backend_servers (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(128) NOT NULL,
  ip            VARCHAR(64)  NOT NULL,
  external_ref  VARCHAR(128) NOT NULL DEFAULT '',
  reseller_id   BIGINT UNSIGNED NULL,
  notes         VARCHAR(512) NOT NULL DEFAULT '',
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_backend_servers_reseller (reseller_id),
  CONSTRAINT fk_backend_servers_reseller FOREIGN KEY (reseller_id) REFERENCES resellers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backend_servers;
-- +goose StatementEnd
