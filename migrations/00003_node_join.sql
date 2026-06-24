-- +goose Up
-- +goose StatementBegin
CREATE TABLE node_join_tokens (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  token_hash    VARCHAR(255) NOT NULL,
  token_prefix  CHAR(12) NOT NULL,
  node_group_id BIGINT UNSIGNED NOT NULL,
  max_routes    INT NOT NULL DEFAULT 1000,
  priority      INT NOT NULL DEFAULT 100,
  name_hint     VARCHAR(128),
  created_by    BIGINT UNSIGNED,
  expires_at    TIMESTAMP NOT NULL,
  used_at       TIMESTAMP NULL,
  used_node_id  BIGINT UNSIGNED NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_jt_prefix (token_prefix),
  KEY idx_jt_expires (expires_at),
  CONSTRAINT fk_jt_group FOREIGN KEY (node_group_id) REFERENCES node_groups(id),
  CONSTRAINT fk_jt_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE caddy_nodes
  ADD COLUMN wg_ip          VARCHAR(45)  NULL AFTER public_ip,
  ADD COLUMN wg_public_key  VARCHAR(255) NULL AFTER wg_ip,
  ADD UNIQUE KEY uq_nodes_wg_ip (wg_ip);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE caddy_nodes DROP COLUMN wg_public_key, DROP COLUMN wg_ip;
DROP TABLE IF EXISTS node_join_tokens;
-- +goose StatementEnd
