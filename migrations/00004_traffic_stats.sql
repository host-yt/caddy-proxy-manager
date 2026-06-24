-- +goose Up
-- +goose StatementBegin
CREATE TABLE node_traffic_samples (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id         BIGINT UNSIGNED NOT NULL,
  sampled_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  requests_total  BIGINT UNSIGNED NOT NULL DEFAULT 0,
  errors_total    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_in_total  BIGINT UNSIGNED NOT NULL DEFAULT 0,
  bytes_out_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
  active_conns    INT UNSIGNED NOT NULL DEFAULT 0,
  KEY idx_nts_node_time (node_id, sampled_at),
  CONSTRAINT fk_nts_node FOREIGN KEY (node_id) REFERENCES caddy_nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS node_traffic_samples;
-- +goose StatementEnd
