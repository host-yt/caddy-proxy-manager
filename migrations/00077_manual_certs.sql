-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig77_up;
CREATE PROCEDURE hpg_mig77_up()
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='manual_certs') THEN
        CREATE TABLE manual_certs (
            id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            -- operator label for this cert (freeform, not unique)
            name         VARCHAR(255)    NOT NULL DEFAULT '',
            -- optional: link to a proxy route; NULL = unattached
            route_id     BIGINT UNSIGNED NULL,
            cert_pem     MEDIUMTEXT      NOT NULL,
            -- private key encrypted at rest via installstate AES-256-GCM
            key_pem_enc  MEDIUMTEXT      NOT NULL,
            chain_pem    MEDIUMTEXT      NOT NULL,
            common_name  VARCHAR(255)    NOT NULL DEFAULT '',
            -- JSON array of SAN strings, e.g. '["example.com","www.example.com"]'
            sans         TEXT            NOT NULL,
            not_before   DATETIME        NOT NULL,
            not_after    DATETIME        NOT NULL,
            created_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            INDEX idx_mc_not_after (not_after),
            INDEX idx_mc_route    (route_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig77_up();
DROP PROCEDURE IF EXISTS hpg_mig77_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS manual_certs;
-- +goose StatementEnd
