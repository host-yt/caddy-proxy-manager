-- +goose Up
-- +goose StatementBegin
CREATE TABLE backup_destinations (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(128) NOT NULL,
  kind         ENUM('sftp','ftp','s3','local') NOT NULL,
  config_enc   MEDIUMTEXT NOT NULL,
  is_enabled   TINYINT(1) NOT NULL DEFAULT 1,
  created_by   BIGINT UNSIGNED NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_bd_name (name),
  KEY idx_bd_kind (kind),
  CONSTRAINT fk_bd_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE backup_jobs (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  destination_id  BIGINT UNSIGNED NOT NULL,
  kind            ENUM('manual','scheduled') NOT NULL DEFAULT 'manual',
  status          ENUM('pending','running','succeeded','failed') NOT NULL DEFAULT 'pending',
  artifact_key    VARCHAR(512),
  size_bytes      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  sha256          CHAR(64),
  encrypted       TINYINT(1) NOT NULL DEFAULT 1,
  started_at      TIMESTAMP NULL,
  finished_at     TIMESTAMP NULL,
  error_text      TEXT,
  triggered_by    BIGINT UNSIGNED NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_bj_dest (destination_id),
  KEY idx_bj_status (status),
  KEY idx_bj_created (created_at),
  CONSTRAINT fk_bj_dest FOREIGN KEY (destination_id) REFERENCES backup_destinations(id) ON DELETE CASCADE,
  CONSTRAINT fk_bj_user FOREIGN KEY (triggered_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backup_jobs;
DROP TABLE IF EXISTS backup_destinations;
-- +goose StatementEnd
