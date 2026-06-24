package routes

// Route = domain[+path] -> service.backend_ip:port mapping.
// Lifecycle states:
//   pending_dns -> dns_ok -> pending_ssl -> active
//   any -> failed (with error reason)
//
// Caddy push: on state transition to dns_ok we PATCH the assigned node's
// Caddy config. ACME issuance happens automatically via On-Demand TLS
// (gated by /internal/ask).
