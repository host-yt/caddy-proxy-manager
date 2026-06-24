// Package queue runs async jobs via asynq (Redis-backed).
//
// Jobs: DNS verify, SSL retry, route propagation to nodes, email send,
// node health probes. Use queue.Enqueue from handlers for any work that
// can be deferred - keeps request latency low.
package queue
