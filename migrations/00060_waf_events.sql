-- +goose Up
-- +goose StatementBegin
CREATE TABLE waf_events (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  route_id   BIGINT UNSIGNED NULL,          -- soft ref to routes.id; no FK to avoid cascade
  ts         DATETIME NOT NULL,
  severity   VARCHAR(16) NOT NULL DEFAULT 'low',
  rule_id    VARCHAR(128) NOT NULL DEFAULT '',
  action     VARCHAR(16) NOT NULL DEFAULT 'detected',
  remote_ip  VARCHAR(64) NOT NULL DEFAULT '',
  host       VARCHAR(255) NOT NULL DEFAULT '',
  uri        VARCHAR(512) NOT NULL DEFAULT '',
  message    VARCHAR(512) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_waf_route_ts  (route_id, ts),
  KEY idx_waf_severity  (severity),
  KEY idx_waf_remote_ip (remote_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS waf_events;
-- +goose StatementEnd
