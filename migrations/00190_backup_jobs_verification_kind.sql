-- +goose Up
-- +goose StatementBegin
ALTER TABLE backup_jobs MODIFY kind ENUM('manual','scheduled','verification') NOT NULL DEFAULT 'manual';
-- +goose StatementEnd
-- +goose StatementBegin
-- Verify used to log as 'manual' with a fake "verify_" key that later Verify/drill runs picked as the source backup.
UPDATE backup_jobs SET kind = 'verification', artifact_key = NULL
 WHERE SUBSTR(artifact_key, 1, 7) = 'verify_';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE backup_jobs SET kind = 'manual' WHERE kind = 'verification';
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE backup_jobs MODIFY kind ENUM('manual','scheduled') NOT NULL DEFAULT 'manual';
-- +goose StatementEnd
