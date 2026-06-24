package services

// Service = customer VPS record. Fields:
//   id, client_id, name, backend_ip, allowed_port_start, allowed_port_end,
//   plan_id, node_group_id, status, external_reference, notes
//
// INVARIANT: backend_ip and allowed port range are SET ONLY by admin or API
// (FOSSBilling provisioning). The client UI exposes these as read-only.
// Any handler that accepts these fields from a client session is a bug.
