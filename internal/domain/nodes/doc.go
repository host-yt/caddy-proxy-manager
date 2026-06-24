package nodes

// Node placement algorithm for new routes:
//   1. Filter: enabled=true, current_routes<max_routes, node_group matches plan
//   2. Pick lowest usage (current_routes / max_routes)
//   3. Tie-break: higher priority wins
//   4. No node available -> caller returns 409 with clear message
//
// Future modes: active-active (write to all nodes in group), failover (primary
// + standby). For MVP we do single-node placement.
