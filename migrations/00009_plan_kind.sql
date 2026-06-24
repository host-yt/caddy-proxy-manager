-- +goose Up
-- +goose StatementBegin
-- Plans gain a `kind` discriminator so the operator can sell two flavours
-- from the same panel:
--   * 'restricted'  - current behaviour: admin pins backend_ip and the
--                     allowed_port range on every service; client only
--                     picks domain + port from that range.
--   * 'npm'         - full self-service (NPM-like): client may edit the
--                     service's backend_ip and port range themselves.
-- Existing rows default to 'restricted' to preserve current invariants
-- (hard rule #1 still applies unless the operator deliberately
-- creates an 'npm' plan).
ALTER TABLE plans
  ADD COLUMN kind ENUM('restricted','npm') NOT NULL DEFAULT 'restricted'
    AFTER name;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE plans DROP COLUMN kind;
-- +goose StatementEnd
