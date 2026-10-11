-- +goose Up
-- +goose StatementBegin
-- Provider records the DNS steering reconciler created. No FKs on purpose:
-- ownership must outlive a deleted route/node/assignment so the leftover
-- record can still be deleted at the provider.
CREATE TABLE IF NOT EXISTS dns_steering_records (
  route_id        BIGINT UNSIGNED NOT NULL,
  node_id         BIGINT UNSIGNED NOT NULL,
  dns_provider_id BIGINT UNSIGNED NOT NULL,
  record_name     VARCHAR(255) NOT NULL,
  record_value    VARCHAR(45) NOT NULL,
  record_id       VARCHAR(64) NOT NULL DEFAULT '',
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (route_id, node_id, record_value),
  KEY idx_dsr_provider (dns_provider_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- present=1 is only ever written after the reconciler's own add.
INSERT IGNORE INTO dns_steering_records (route_id, node_id, dns_provider_id, record_name, record_value)
SELECT s.route_id, s.node_id, r.dns_provider_id, r.domain, s.record_value
  FROM dns_steering_state s
  JOIN routes r ON r.id = s.route_id
 WHERE s.present = 1 AND r.dns_provider_id IS NOT NULL AND s.record_value <> '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dns_steering_records;
-- +goose StatementEnd
