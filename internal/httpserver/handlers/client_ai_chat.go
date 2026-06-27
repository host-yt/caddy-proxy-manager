package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/aichat"
	"github.com/host-yt/caddy-proxy-manager/internal/chatstore"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// clientStreamReply runs plain StreamChat for client-scope requests. It returns
// the buffered reply and false when the client disconnected or an error was emitted.
func clientStreamReply(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, client aichat.Client, msgs []aichat.Message, log *slog.Logger) (string, bool) {
	ch, err := client.StreamChat(ctx, msgs, aichat.Options{Temperature: -1})
	if err != nil {
		sseError(w, rc, "AI request failed")
		return "", false
	}
	var b strings.Builder
	for chunk := range ch {
		if chunk.Err != nil {
			log.Warn("app ai chat stream", "err", chunk.Err)
			sseError(w, rc, "stream error")
			return "", false
		}
		if chunk.Text != "" && b.Len() < chatAssistantCap {
			b.WriteString(chunk.Text)
			payload, _ := json.Marshal(map[string]string{"text": chunk.Text})
			if _, werr := w.Write([]byte("data: " + string(payload) + "\n\n")); werr != nil {
				return "", false
			}
			rc.Flush()
		}
		if chunk.Done {
			break
		}
	}
	return b.String(), true
}

// clientChatUserID returns the session user ID or 0 when unauthenticated.
func clientChatUserID(r *http.Request) int64 {
	if sess := middleware.SessionFromContext(r.Context()); sess != nil {
		return sess.UserID
	}
	return 0
}

// AppAIChatListSessions GET /app/ai/chat/sessions -> {"sessions":[...]}.
func (h *ClientHandlers) AppAIChatListSessions(w http.ResponseWriter, r *http.Request) {
	uid := clientChatUserID(r)
	if uid == 0 || h.ChatStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sessions, err := h.ChatStore.ListSessions(ctx, uid, 100, 0)
	if err != nil {
		h.Logger.Warn("app ai chat list sessions", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	type row struct {
		ID        int64  `json:"id"`
		Title     string `json:"title"`
		Provider  string `json:"provider"`
		UpdatedAt string `json:"updated_at"`
	}
	out := make([]row, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, row{ID: s.ID, Title: s.Title, Provider: s.Provider,
			UpdatedAt: s.UpdatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// AppAIChatCreateSession POST /app/ai/chat/sessions body {"title","provider"} -> {"id"}.
func (h *ClientHandlers) AppAIChatCreateSession(w http.ResponseWriter, r *http.Request) {
	uid := clientChatUserID(r)
	if uid == 0 || h.ChatStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "not available"})
		return
	}
	var body struct {
		Title    string `json:"title"`
		Provider string `json:"provider"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body)
	title := strings.TrimSpace(body.Title)
	if title == "" {
		title = "New chat"
	}
	if len(title) > 200 {
		title = title[:200]
	}
	provider := strings.ToLower(strings.TrimSpace(body.Provider))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	id, err := h.ChatStore.CreateSession(ctx, uid, title, provider)
	if err != nil {
		h.Logger.Warn("app ai chat create session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// AppAIChatGetSession GET /app/ai/chat/sessions/{id} -> session + messages; 404 if not owned.
func (h *ClientHandlers) AppAIChatGetSession(w http.ResponseWriter, r *http.Request) {
	uid := clientChatUserID(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if uid == 0 || id == 0 || h.ChatStore == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sess, msgs, err := h.ChatStore.GetSession(ctx, uid, id)
	if errors.Is(err, chatstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if err != nil {
		h.Logger.Warn("app ai chat get session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	type msgRow struct {
		Role      string `json:"role"`
		Content   string `json:"content"`
		CreatedAt string `json:"created_at"`
	}
	mout := make([]msgRow, 0, len(msgs))
	for _, m := range msgs {
		mout = append(mout, msgRow{Role: m.Role, Content: m.Content,
			CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": sess.ID, "title": sess.Title, "provider": sess.Provider, "messages": mout,
	})
}

// AppAIChatDeleteSession DELETE /app/ai/chat/sessions/{id} -> 204; 404 if not owned.
func (h *ClientHandlers) AppAIChatDeleteSession(w http.ResponseWriter, r *http.Request) {
	uid := clientChatUserID(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if uid == 0 || id == 0 || h.ChatStore == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := h.ChatStore.DeleteSession(ctx, uid, id)
	if errors.Is(err, chatstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if err != nil {
		h.Logger.Warn("app ai chat delete session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "delete failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AppAIChatSendMessage POST /app/ai/chat/sessions/{id}/message streams the reply over SSE.
// Tools are NOT offered to clients (scope is client-only, no admin data access).
func (h *ClientHandlers) AppAIChatSendMessage(w http.ResponseWriter, r *http.Request) {
	uid := clientChatUserID(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if uid == 0 || id == 0 || h.ChatStore == nil || h.AIFactory == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "not available"})
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	content := strings.TrimSpace(body.Content)
	if content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty message"})
		return
	}

	getCtx, getCancel := context.WithTimeout(r.Context(), 5*time.Second)
	_, history, err := h.ChatStore.GetSession(getCtx, uid, id)
	getCancel()
	if errors.Is(err, chatstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if err != nil {
		h.Logger.Warn("app ai chat send: get session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}

	clientCtx, clientCancel := context.WithTimeout(r.Context(), 10*time.Second)
	aiClient, err := h.AIFactory.Default(clientCtx)
	clientCancel()
	if err != nil {
		if errors.Is(err, aichat.ErrNotConfigured) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "AI provider not configured"})
			return
		}
		h.Logger.Warn("app ai chat send: factory")
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "AI provider unavailable"})
		return
	}

	persistCtx, persistCancel := context.WithTimeout(r.Context(), 5*time.Second)
	if _, err := h.ChatStore.AppendMessage(persistCtx, id, "user", content); err != nil {
		persistCancel()
		h.Logger.Warn("app ai chat send: append user", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "save failed"})
		return
	}
	persistCancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	_ = rc.SetWriteDeadline(time.Time{})

	streamCtx, streamCancel := context.WithCancel(r.Context())
	defer streamCancel()

	// Client scope: plain streaming, no tools (tools expose admin-level data).
	msgs := buildChatMessages(history, content)
	streamed, ok := clientStreamReply(streamCtx, w, rc, aiClient, msgs, h.Logger)
	if !ok {
		return
	}

	saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	assistantID, serr := h.ChatStore.AppendMessage(saveCtx, id, "assistant", streamed)
	saveCancel()
	if serr != nil {
		h.Logger.Warn("app ai chat send: append assistant", "err", serr)
		sseError(w, rc, "save failed")
		return
	}

	// Auto-title when enough turns have accumulated.
	if total := len(history) + 2; total >= aiChatAutoTitleAt {
		if title := firstUserTitle(history, content); title != "" {
			tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = h.ChatStore.UpdateTitle(tctx, uid, id, title)
			tcancel()
		}
	}

	donePayload, _ := json.Marshal(map[string]any{"id": assistantID})
	_, _ = w.Write([]byte("event: done\ndata: " + string(donePayload) + "\n\n"))
	rc.Flush()
}
