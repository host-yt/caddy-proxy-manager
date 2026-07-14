-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS node_rtt_samples (
  node_id      BIGINT UNSIGNED NOT NULL,
  bucket_start TIMESTAMP NOT NULL,
  rtt_ms_avg   INT NOT NULL,
  rtt_ms_min   INT NOT NULL,
  rtt_ms_max   INT NOT NULL,
  samples      INT NOT NULL DEFAULT 1,
  PRIMARY KEY (node_id, bucket_start),
  CONSTRAINT fk_node_rtt_samples_node FOREIGN KEY (node_id) REFERENCES caddy_nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig131_up;
CREATE PROCEDURE hpg_mig131_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='last_rtt_ms') THEN
        ALTER TABLE caddy_nodes ADD COLUMN last_rtt_ms INT NULL AFTER health_status;
    END IF;
END;
CALL hpg_mig131_up();
DROP PROCEDURE IF EXISTS hpg_mig131_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig131_down;
CREATE PROCEDURE hpg_mig131_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='caddy_nodes' AND COLUMN_NAME='last_rtt_ms') THEN
        ALTER TABLE caddy_nodes DROP COLUMN last_rtt_ms;
    END IF;
END;
CALL hpg_mig131_down();
DROP PROCEDURE IF EXISTS hpg_mig131_down;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS node_rtt_samples;
-- +goose StatementEnd
