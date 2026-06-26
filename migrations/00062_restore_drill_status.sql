-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS restore_drill_status (
  id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  started_at      DATETIME NOT NULL,
  finished_at     DATETIME NOT NULL,
  success         TINYINT(1) NOT NULL DEFAULT 0,
  rows_replayed   INT NULL,
  error_message   VARCHAR(512) NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_restore_drill_started (started_at DESC)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS restore_drill_status;
-- +goose StatementEnd
