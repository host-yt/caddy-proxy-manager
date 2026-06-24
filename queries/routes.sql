-- name: GetRouteByDomain :one
-- Hot path for /internal/ask. Must be indexed (uq_route_domain_path covers exact lookup).
SELECT id, service_id, caddy_node_id, domain, path_prefix, status, ssl_enabled
FROM routes
WHERE domain = ? AND status IN ('active','pending_ssl')
LIMIT 1;

-- name: ListRoutesByService :many
SELECT *
FROM routes
WHERE service_id = ?
ORDER BY created_at DESC;

-- name: CreateRoute :execresult
INSERT INTO routes (
  service_id, caddy_node_id, domain, path_prefix, upstream_port,
  ssl_enabled, websocket, force_https, http2_enabled, http3_enabled, status
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_dns');

-- name: UpdateRouteStatus :exec
UPDATE routes SET status = ?, last_error = ?, updated_at = NOW() WHERE id = ?;

-- name: DeleteRoute :exec
DELETE FROM routes WHERE id = ?;
