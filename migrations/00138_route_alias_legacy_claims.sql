-- +goose Up
-- +goose StatementBegin
-- 00136 backfilled aliases_verified straight from aliases, turning every
-- historical claim into ownership proof. Park those claims here so a platform
-- admin can review/approve them after the proof is dropped below.
CREATE TABLE IF NOT EXISTS route_alias_legacy_claims (
  route_id    BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  aliases     TEXT NOT NULL,
  status      VARCHAR(16) NOT NULL DEFAULT 'pending',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TIMESTAMP NULL,
  resolved_by BIGINT UNSIGNED NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO route_alias_legacy_claims (route_id, aliases)
SELECT id, aliases_verified FROM routes
 WHERE aliases_verified IS NOT NULL AND aliases_verified <> '';
-- +goose StatementEnd

-- +goose StatementBegin
-- Breaking on purpose: an unproven alias stops being emitted and stops being
-- cert-eligible. RecheckPendingAliases re-proves it automatically once the
-- owner's _hpg-verify.<alias> TXT record is in place.
UPDATE routes SET aliases_verified = NULL
 WHERE aliases_verified IS NOT NULL AND aliases_verified <> '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE routes SET aliases_verified = (
  SELECT aliases FROM route_alias_legacy_claims c WHERE c.route_id = routes.id
) WHERE id IN (SELECT route_id FROM route_alias_legacy_claims);
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS route_alias_legacy_claims;
-- +goose StatementEnd
