-- +goose Up
-- +goose StatementBegin
-- Ingested access-log batch ids (sha256 of node id + body). A node agent
-- resends a batch whose ack it never saw; the ledger turns that into a no-op.
-- batch_hash (not *_key): length-typed *_key columns break the SQLite transform.
CREATE TABLE IF NOT EXISTS access_log_batches (
  batch_hash CHAR(64) NOT NULL PRIMARY KEY,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_alb_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS access_log_batches;
-- +goose StatementEnd
