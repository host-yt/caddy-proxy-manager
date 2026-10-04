-- +goose Up
-- +goose StatementBegin
-- Durable "node X needs a push" marker, written with the config change so a
-- crash between commit and push is repaired by the leader's drain.
CREATE TABLE IF NOT EXISTS node_push_pending (
  node_id         BIGINT UNSIGNED NOT NULL,
  seq             BIGINT NOT NULL DEFAULT 1,
  requested_at    DATETIME NOT NULL,
  attempts        INT NOT NULL DEFAULT 0,
  last_error      TEXT NULL,
  next_attempt_at DATETIME NOT NULL,
  PRIMARY KEY (node_id),
  CONSTRAINT fk_node_push_pending_node FOREIGN KEY (node_id) REFERENCES caddy_nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS node_push_pending;
-- +goose StatementEnd
