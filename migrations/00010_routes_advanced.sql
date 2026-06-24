-- +goose Up
-- +goose StatementBegin
-- Routes get the advanced knobs NPM users expect: pick between a
-- reverse-proxy route (default) and a redirect; group by tag; toggle
-- a cheap response cache; attach upstream request headers.
ALTER TABLE routes
  ADD COLUMN kind ENUM('proxy','redirect') NOT NULL DEFAULT 'proxy' AFTER status,
  ADD COLUMN redirect_url    VARCHAR(2048) NULL AFTER kind,
  ADD COLUMN redirect_code   SMALLINT      NULL AFTER redirect_url,
  ADD COLUMN cache_enabled   TINYINT(1)    NOT NULL DEFAULT 0 AFTER redirect_code,
  ADD COLUMN cache_ttl_secs  INT           NOT NULL DEFAULT 60 AFTER cache_enabled,
  ADD COLUMN custom_headers  TEXT          NULL  AFTER cache_ttl_secs,
  ADD COLUMN tag             VARCHAR(64)   NULL  AFTER custom_headers,
  ADD KEY idx_route_tag (tag);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE routes
  DROP KEY idx_route_tag,
  DROP COLUMN tag,
  DROP COLUMN custom_headers,
  DROP COLUMN cache_ttl_secs,
  DROP COLUMN cache_enabled,
  DROP COLUMN redirect_code,
  DROP COLUMN redirect_url,
  DROP COLUMN kind;
-- +goose StatementEnd
