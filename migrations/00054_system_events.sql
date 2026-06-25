CREATE TABLE system_events (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id    BIGINT UNSIGNED NULL,
  route_id   BIGINT UNSIGNED NULL,
  event_type VARCHAR(64) NOT NULL,
  severity   ENUM('info','warn','error') NOT NULL DEFAULT 'info',
  message    TEXT NOT NULL,
  meta       JSON,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_se_type_ts (event_type, created_at DESC),
  KEY idx_se_route (route_id),
  KEY idx_se_node (node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
