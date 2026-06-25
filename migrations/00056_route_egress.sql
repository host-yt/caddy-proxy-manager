-- Outbound/egress IP per route.
-- caddy_nodes.outbound_ips: JSON array of IPs the node may use as egress (informational).
-- routes.outbound_ip_mode: 'default' = let OS pick, 'fixed' = bind to outbound_ip.
-- routes.outbound_ip: the specific IP to bind (must be present on the node NIC).

ALTER TABLE caddy_nodes ADD COLUMN outbound_ips JSON NULL;
ALTER TABLE routes ADD COLUMN outbound_ip_mode ENUM('default','fixed') NOT NULL DEFAULT 'default';
ALTER TABLE routes ADD COLUMN outbound_ip VARCHAR(45) NULL;
