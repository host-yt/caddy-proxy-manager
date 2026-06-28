-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig116_up;
CREATE PROCEDURE hpg_mig116_up()
BEGIN
    -- Named roles scoped to a CA. Roles drive path-based access control.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='mtls_roles') THEN
        CREATE TABLE mtls_roles (
            id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ca_id      BIGINT UNSIGNED NOT NULL,
            name       VARCHAR(64)     NOT NULL,
            created_at TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_mtls_role (ca_id, name),
            CONSTRAINT fk_mtls_roles_ca FOREIGN KEY (ca_id) REFERENCES mtls_cas(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    -- Cert-to-role mapping (many-to-many).
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='mtls_cert_roles') THEN
        CREATE TABLE mtls_cert_roles (
            cert_id   BIGINT UNSIGNED NOT NULL,
            role_id   BIGINT UNSIGNED NOT NULL,
            PRIMARY KEY (cert_id, role_id),
            CONSTRAINT fk_mcr_cert FOREIGN KEY (cert_id) REFERENCES mtls_issued_certs(id) ON DELETE CASCADE,
            CONSTRAINT fk_mcr_role FOREIGN KEY (role_id) REFERENCES mtls_roles(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;

    -- Per-route path access rules. A request to path_pattern requires the cert to have required_role_id.
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='mtls_path_rules') THEN
        CREATE TABLE mtls_path_rules (
            id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            route_id         BIGINT UNSIGNED NOT NULL,
            path_pattern     VARCHAR(255)    NOT NULL,
            required_role_id BIGINT UNSIGNED NOT NULL,
            created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            INDEX idx_mpr_route (route_id),
            CONSTRAINT fk_mpr_route FOREIGN KEY (route_id) REFERENCES routes(id) ON DELETE CASCADE,
            CONSTRAINT fk_mpr_role  FOREIGN KEY (required_role_id) REFERENCES mtls_roles(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    END IF;
END;
CALL hpg_mig116_up();
DROP PROCEDURE IF EXISTS hpg_mig116_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS mtls_path_rules;
DROP TABLE IF EXISTS mtls_cert_roles;
DROP TABLE IF EXISTS mtls_roles;
-- +goose StatementEnd
