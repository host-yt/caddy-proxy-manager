-- +goose Up
-- +goose StatementBegin
-- Time-based retention for AI chat transcripts (AI-04). Default 365 days;
-- 0 disables pruning. Sessions older than this by last activity (updated_at)
-- are deleted; ai_chat_messages cascade via FK.
INSERT IGNORE INTO settings (`key`, value, is_encrypted) VALUES
('ai.chat_retention_days', '365', 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE `key` = 'ai.chat_retention_days';
-- +goose StatementEnd
