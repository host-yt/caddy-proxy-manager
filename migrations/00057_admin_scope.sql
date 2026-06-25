-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS admin_client_scope (
  admin_user_id BIGINT UNSIGNED NOT NULL,
  client_id     BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (admin_user_id, client_id),
  KEY idx_acs_admin (admin_user_id),
  CONSTRAINT fk_acs_user   FOREIGN KEY (admin_user_id) REFERENCES users(id)   ON DELETE CASCADE,
  CONSTRAINT fk_acs_client FOREIGN KEY (client_id)     REFERENCES clients(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_client_scope;
-- +goose StatementEnd
