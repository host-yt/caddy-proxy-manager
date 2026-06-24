-- +goose Up
CREATE TABLE stream_routes (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  service_id      BIGINT UNSIGNED NOT NULL,
  caddy_node_id   BIGINT UNSIGNED NOT NULL,
  protocol        ENUM('tcp','udp','both') NOT NULL DEFAULT 'tcp',
  listen_port     INT NOT NULL,
  upstream_port   INT NOT NULL,
  status          ENUM('active','disabled') NOT NULL DEFAULT 'active',
  tag             VARCHAR(64) NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_stream_port_proto (caddy_node_id, listen_port, protocol),
  KEY idx_stream_service (service_id),
  CONSTRAINT fk_stream_svc  FOREIGN KEY (service_id)    REFERENCES services(id) ON DELETE CASCADE,
  CONSTRAINT fk_stream_node FOREIGN KEY (caddy_node_id) REFERENCES caddy_nodes(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
DROP TABLE stream_routes;
