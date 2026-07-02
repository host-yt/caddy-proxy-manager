-- +goose Up
-- +goose StatementBegin
-- Domain-ownership gate for self-service routes. Without this a tenant can
-- pre-claim ANY hostname (e.g. app.bigcorp.com); once the real owner points DNS
-- at the shared node the squatter's route advances and Caddy issues a valid LE
-- cert for the victim host. domain_verified=0 blocks cert issuance (caddy_ask)
-- and route advancement past pending_dns until a DNS TXT proof clears it.
-- verify_token holds the per-route hex nonce the owner publishes at
-- _hpg-verify.<domain>. Named verify_token (not *_key/*_index with a length
-- type) to dodge the MySQL->SQLite inline-index transformer trap.
ALTER TABLE routes
    ADD COLUMN domain_verified TINYINT NOT NULL DEFAULT 0,
    ADD COLUMN verify_token    VARCHAR(64) NOT NULL DEFAULT '';
-- +goose StatementEnd
-- +goose StatementBegin
-- Grandfather every EXISTING route so production keeps serving. Only routes
-- created after this migration land unverified and must prove ownership.
UPDATE routes SET domain_verified = 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE routes
    DROP COLUMN verify_token,
    DROP COLUMN domain_verified;
-- +goose StatementEnd
