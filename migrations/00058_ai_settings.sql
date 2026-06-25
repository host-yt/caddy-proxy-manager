-- +goose Up
-- +goose StatementBegin
INSERT IGNORE INTO settings (`key`, value, is_encrypted) VALUES
('ai.default_provider', '', 0),
('ai.anthropic_key_enc', '', 1),
('ai.openai_key_enc', '', 1),
('ai.gemini_key_enc', '', 1),
('ai.openrouter_key_enc', '', 1);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings
WHERE `key` IN (
  'ai.default_provider',
  'ai.anthropic_key_enc',
  'ai.openai_key_enc',
  'ai.gemini_key_enc',
  'ai.openrouter_key_enc'
);
-- +goose StatementEnd
