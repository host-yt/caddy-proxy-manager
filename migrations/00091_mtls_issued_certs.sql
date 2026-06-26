-- +goose Up
-- +goose StatementBegin

DROP PROCEDURE IF EXISTS hpg_mig91_up;
CREATE PROCEDURE hpg_mig91_up()
BEGIN
    -- Client certificates issued from an mtls_cas CA. Status drives a CRL-style
    -- revocation list (active|revoked). Only the public cert PEM is stored here;
    -- the client private key is returned once at issue time and never persisted.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='mtls_issued_certs') THEN
        CREATE TABLE mtls_issued_certs (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ca_id       BIGINT UNSIGNED NOT NULL,
            subject     VARCHAR(255)    NOT NULL DEFAULT '',
            -- decimal serial string, unique within the issuing CA
            serial      VARCHAR(80)     NOT NULL,
            cert_pem    MEDIUMTEXT      NOT NULL,
            status      VARCHAR(16)     NOT NULL DEFAULT 'active',
            not_after   DATETIME        NOT NULL,
            issued_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            revoked_at  DATETIME        NULL,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mtls_issued_serial (ca_id, serial),
            INDEX idx_mtls_issued_ca (ca_id),
            INDEX idx_mtls_issued_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig91_up();
DROP PROCEDURE IF EXISTS hpg_mig91_up;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS mtls_issued_certs;
-- +goose StatementEnd
