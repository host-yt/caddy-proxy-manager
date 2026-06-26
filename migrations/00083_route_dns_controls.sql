-- +goose Up
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig83_up;
CREATE PROCEDURE hpg_mig83_up()
BEGIN
    -- Custom DNS resolver IP for upstream hostname resolution (IPv4 or IPv6).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_resolver_ip') THEN
        ALTER TABLE routes ADD COLUMN dns_resolver_ip VARCHAR(45) NULL AFTER geo_countries;
    END IF;
    -- Resolve upstream via a WG peer's DNS (peer must run dnsmasq/coredns on :53).
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_resolver_via_wg_peer_id') THEN
        ALTER TABLE routes ADD COLUMN dns_resolver_via_wg_peer_id BIGINT UNSIGNED NULL AFTER dns_resolver_ip;
    END IF;
    -- Address-family preference: 'any'/'ipv4' use A records, 'ipv6' uses AAAA records.
    IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_address_family') THEN
        ALTER TABLE routes ADD COLUMN dns_address_family VARCHAR(8) NOT NULL DEFAULT 'any' AFTER dns_resolver_via_wg_peer_id;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_route_dns_wgpeer') THEN
        ALTER TABLE routes ADD CONSTRAINT fk_route_dns_wgpeer FOREIGN KEY (dns_resolver_via_wg_peer_id) REFERENCES customer_wg_peer(id) ON DELETE SET NULL;
    END IF;
END;
CALL hpg_mig83_up();
DROP PROCEDURE hpg_mig83_up;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP PROCEDURE IF EXISTS hpg_mig83_down;
CREATE PROCEDURE hpg_mig83_down()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_address_family') THEN
        ALTER TABLE routes DROP COLUMN dns_address_family;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND CONSTRAINT_NAME='fk_route_dns_wgpeer') THEN
        ALTER TABLE routes DROP FOREIGN KEY fk_route_dns_wgpeer;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_resolver_via_wg_peer_id') THEN
        ALTER TABLE routes DROP COLUMN dns_resolver_via_wg_peer_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='routes' AND COLUMN_NAME='dns_resolver_ip') THEN
        ALTER TABLE routes DROP COLUMN dns_resolver_ip;
    END IF;
END;
CALL hpg_mig83_down();
DROP PROCEDURE hpg_mig83_down;
-- +goose StatementEnd
