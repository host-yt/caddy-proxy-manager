-- +goose Up
ALTER TABLE host_access_log
  ADD COLUMN asn_org VARCHAR(128) NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE host_access_log
  DROP COLUMN asn_org;
