-- +goose Up
CREATE TABLE route_basic_auth_users (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    route_id    BIGINT UNSIGNED NOT NULL,
    username    VARCHAR(128) NOT NULL,
    bcrypt_hash VARCHAR(120) NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_rbu_route_user (route_id, username),
    INDEX idx_rbu_route (route_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO route_basic_auth_users (route_id, username, bcrypt_hash)
SELECT id, basic_auth_user, basic_auth_bcrypt
FROM routes
WHERE basic_auth_user <> '' AND basic_auth_bcrypt <> '';

-- +goose Down
DROP TABLE IF EXISTS route_basic_auth_users;
