-- +goose Up
-- +goose StatementBegin
-- Per-provider selected model. Plaintext, optional; empty = adapter default.
INSERT IGNORE INTO settings (`key`, value, is_encrypted) VALUES
('ai.anthropic_model', '', 0),
('ai.openai_model', '', 0),
('ai.gemini_model', '', 0),
('ai.openrouter_model', '', 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings
WHERE `key` IN (
  'ai.anthropic_model',
  'ai.openai_model',
  'ai.gemini_model',
  'ai.openrouter_model'
);
-- +goose StatementEnd
