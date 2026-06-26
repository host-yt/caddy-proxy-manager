// Package chatstore provides DB access for AI chat sessions and messages.
// All methods are ownership-scoped by user_id to prevent cross-user data leaks.
package chatstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a session does not exist or belongs to another user.
var ErrNotFound = errors.New("chatstore: session not found")

// Session represents a single AI chat thread.
type Session struct {
	ID        int64
	UserID    int64
	Title     string
	Provider  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Message is one turn within a session.
type Message struct {
	ID        int64
	SessionID int64
	Role      string // user | assistant | system | tool
	Content   string
	CreatedAt time.Time
}

// Store wraps a *sql.DB with chat-specific queries.
type Store struct {
	db *sql.DB
}

// New returns a Store backed by db.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateSession inserts a new session row and returns its auto-increment id.
func (s *Store) CreateSession(ctx context.Context, userID int64, title, provider string) (int64, error) {
	const q = `INSERT INTO ai_chat_sessions (user_id, title, provider) VALUES (?, ?, ?)`
	res, err := s.db.ExecContext(ctx, q, userID, title, provider)
	if err != nil {
		return 0, fmt.Errorf("chatstore: create session: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("chatstore: create session last-id: %w", err)
	}
	return id, nil
}

// AppendMessage inserts a message into an existing session and returns its id.
// No ownership check here - callers must have verified session ownership first.
func (s *Store) AppendMessage(ctx context.Context, sessionID int64, role, content string) (int64, error) {
	const q = `INSERT INTO ai_chat_messages (session_id, role, content) VALUES (?, ?, ?)`
	res, err := s.db.ExecContext(ctx, q, sessionID, role, content)
	if err != nil {
		return 0, fmt.Errorf("chatstore: append message: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("chatstore: append message last-id: %w", err)
	}
	return id, nil
}

// ListSessions returns sessions owned by userID, newest first, with pagination.
func (s *Store) ListSessions(ctx context.Context, userID int64, limit, offset int) ([]Session, error) {
	const q = `
		SELECT id, user_id, title, provider, created_at, updated_at
		FROM ai_chat_sessions
		WHERE user_id = ?
		ORDER BY updated_at DESC
		LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("chatstore: list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Title, &sess.Provider,
			&sess.CreatedAt, &sess.UpdatedAt); err != nil {
			return nil, fmt.Errorf("chatstore: list sessions scan: %w", err)
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("chatstore: list sessions rows: %w", err)
	}
	return sessions, nil
}

// GetSession returns the session header and all its messages.
// Returns ErrNotFound if the session does not exist or belongs to a different user.
func (s *Store) GetSession(ctx context.Context, userID, sessionID int64) (Session, []Message, error) {
	const sq = `
		SELECT id, user_id, title, provider, created_at, updated_at
		FROM ai_chat_sessions
		WHERE id = ? AND user_id = ?`
	var sess Session
	err := s.db.QueryRowContext(ctx, sq, sessionID, userID).Scan(
		&sess.ID, &sess.UserID, &sess.Title, &sess.Provider,
		&sess.CreatedAt, &sess.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, nil, ErrNotFound
	}
	if err != nil {
		return Session{}, nil, fmt.Errorf("chatstore: get session: %w", err)
	}

	const mq = `
		SELECT id, session_id, role, content, created_at
		FROM ai_chat_messages
		WHERE session_id = ?
		ORDER BY id ASC`
	rows, err := s.db.QueryContext(ctx, mq, sessionID)
	if err != nil {
		return Session{}, nil, fmt.Errorf("chatstore: get session messages: %w", err)
	}
	defer rows.Close()

	var msgs []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Role, &m.Content, &m.CreatedAt); err != nil {
			return Session{}, nil, fmt.Errorf("chatstore: get session messages scan: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return Session{}, nil, fmt.Errorf("chatstore: get session messages rows: %w", err)
	}
	return sess, msgs, nil
}

// DeleteSession removes a session and all its messages (FK cascade).
// Returns ErrNotFound if the session does not exist or belongs to a different user.
func (s *Store) DeleteSession(ctx context.Context, userID, sessionID int64) error {
	const q = `DELETE FROM ai_chat_sessions WHERE id = ? AND user_id = ?`
	res, err := s.db.ExecContext(ctx, q, sessionID, userID)
	if err != nil {
		return fmt.Errorf("chatstore: delete session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("chatstore: delete session affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
