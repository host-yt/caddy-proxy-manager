-- +goose Up
-- +goose StatementBegin
-- Time-based PII retention for host_access_log (DB-04). Default 90 days;
-- 0 disables time pruning (the per-route row cap still applies at insert).
INSERT IGNORE INTO settings (`key`, value, is_encrypted) VALUES
('analytics.access_log_retention_days', '90', 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE `key` = 'analytics.access_log_retention_days';
-- +goose StatementEnd
