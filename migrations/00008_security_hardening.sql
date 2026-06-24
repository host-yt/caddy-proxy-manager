-- +goose Up
-- +goose StatementBegin
-- Audit reviewer P1: api_keys.key_prefix had only a non-unique index. A
-- prefix collision (8 base64url chars = 48 bits, birthday at ~16M keys, but
-- exploitable earlier via key-create grinding) returns LIMIT 1 ambiguously
-- and the Argon2id fallback path becomes a collision side-channel. UNIQUE
-- forces every prefix to be globally distinct; the API-key issuer must
-- retry on duplicate.
ALTER TABLE api_keys ADD UNIQUE KEY uq_ak_prefix (key_prefix);

-- Defence in depth: bound how long a key_hmac may live without rotation.
-- (Informational column; rotate-secret CLI sets it to NULL.)
-- No structural change needed.
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_keys DROP INDEX uq_ak_prefix;
-- +goose StatementEnd
