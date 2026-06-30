-- +goose Up
-- +goose StatementBegin
-- Persistent dedup ledger for ingested WAF events. The node-agent re-ships its
-- whole Coraza audit log whenever its saved read offset is lost (e.g. a restart
-- with a read-only/ephemeral log volume), which re-POSTed every historical event
-- and resurrected cleared rows. This table records every event identity ever
-- ingested; ingest skips keys it has already seen. "Clear events" deletes from
-- waf_events only and never touches this ledger, so cleared events stay cleared
-- even when replayed. Capped to the newest N rows (PruneSeen) to stay bounded;
-- first_seen + its index drive that ordering.
-- event_hash (not *_key): a column whose name ends in "key" + a length type like
-- CHAR(64) confuses the MySQL->SQLite inline-index transformer.
CREATE TABLE waf_seen_events (
  event_hash CHAR(64) NOT NULL PRIMARY KEY,   -- sha256 hex of node + event identity
  first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_waf_seen_first_seen (first_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS waf_seen_events;
-- +goose StatementEnd
