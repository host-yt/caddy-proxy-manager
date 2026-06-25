-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS route_location_rules (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  route_id        BIGINT UNSIGNED NOT NULL,
  sort_order      INT NOT NULL DEFAULT 0,
  path_glob       VARCHAR(255) NOT NULL,
  action          ENUM('proxy','redirect','block','rewrite') NOT NULL DEFAULT 'proxy',
  upstream_scheme ENUM('http','https') NOT NULL DEFAULT 'http',
  upstream_host   VARCHAR(255) NULL,
  upstream_port   INT NULL,
  redirect_url    TEXT NULL,
  redirect_code   INT NOT NULL DEFAULT 308,
  rewrite_uri     VARCHAR(1024) NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_route_location_rules_route FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
  INDEX idx_route_location_rules_route (route_id, sort_order, id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS route_location_rules;
-- +goose StatementEnd
