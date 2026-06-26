-- +goose Up
-- +goose StatementBegin

-- Multiple upstreams per stream route (weighted LB).
CREATE TABLE stream_upstreams (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  stream_route_id BIGINT UNSIGNED NOT NULL,
  address         VARCHAR(255)    NOT NULL,  -- host:port or ip:port
  weight          INT             NOT NULL DEFAULT 1,
  sort_order      INT             NOT NULL DEFAULT 0,
  created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_su_stream FOREIGN KEY (stream_route_id) REFERENCES stream_routes(id) ON DELETE CASCADE,
  INDEX idx_su_stream (stream_route_id, sort_order, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Advanced options on stream_routes.
ALTER TABLE stream_routes
  ADD COLUMN match_mode      ENUM('any','sni','http_host') NOT NULL DEFAULT 'any'    AFTER upstream_port,
  ADD COLUMN match_values    TEXT                          NULL                      AFTER match_mode,
  ADD COLUMN lb_policy       ENUM('round_robin','random','least_conn','first') NOT NULL DEFAULT 'round_robin' AFTER match_values,
  ADD COLUMN proxy_proto_in  ENUM('none','v1','v2')        NOT NULL DEFAULT 'none'   AFTER lb_policy,
  ADD COLUMN proxy_proto_out ENUM('none','v1','v2')        NOT NULL DEFAULT 'none'   AFTER proxy_proto_in,
  ADD COLUMN cidr_allow      TEXT                          NULL                      AFTER proxy_proto_out,
  ADD COLUMN cidr_deny       TEXT                          NULL                      AFTER cidr_allow;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS stream_upstreams;

ALTER TABLE stream_routes
  DROP COLUMN IF EXISTS match_mode,
  DROP COLUMN IF EXISTS match_values,
  DROP COLUMN IF EXISTS lb_policy,
  DROP COLUMN IF EXISTS proxy_proto_in,
  DROP COLUMN IF EXISTS proxy_proto_out,
  DROP COLUMN IF EXISTS cidr_allow,
  DROP COLUMN IF EXISTS cidr_deny;

-- +goose StatementEnd
