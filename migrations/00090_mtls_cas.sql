-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig90_up;
CREATE PROCEDURE hpg_mig90_up()
BEGIN
    -- Per-tenant/operator mTLS certificate authorities. The CA private key is
    -- stored encrypted at rest (installstate AES-256-GCM); never in plaintext.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='mtls_cas') THEN
        CREATE TABLE mtls_cas (
            id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            -- operator label for this CA (freeform, not unique)
            name          VARCHAR(255)    NOT NULL DEFAULT '',
            -- ownership scope: client_id NULL = global/operator-wide CA
            client_id     BIGINT UNSIGNED NULL,
            common_name   VARCHAR(255)    NOT NULL DEFAULT '',
            cert_pem      MEDIUMTEXT      NOT NULL,
            -- CA private key encrypted at rest via installstate AES-256-GCM
            key_pem_enc   MEDIUMTEXT      NOT NULL,
            -- monotonic counter for issuing unique client-cert serials under this CA
            serial_seq    BIGINT UNSIGNED NOT NULL DEFAULT 1,
            not_before    DATETIME        NOT NULL,
            not_after     DATETIME        NOT NULL,
            status        VARCHAR(16)      NOT NULL DEFAULT 'active',
            created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            INDEX idx_mtls_cas_client (client_id),
            INDEX idx_mtls_cas_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig90_up();
DROP PROCEDURE IF EXISTS hpg_mig90_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS mtls_cas;
-- +goose StatementEnd
