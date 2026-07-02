package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/aichat"
	"github.com/host-yt/caddy-proxy-manager/internal/aitools"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/chatstore"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// chatHistoryLimit bounds how many prior turns we replay into the model so a
// long thread cannot blow up the prompt (and provider cost) without limit.
const chatHistoryLimit = 40

// chatAssistantCap caps the buffered assistant reply we persist (~64KB) so a
// runaway stream cannot exhaust memory or the row size.
const chatAssistantCap = 64 * 1024

// aiChatData backs the "ai_chat" admin page. The template (owned by the
// frontend agent) reads .Data.AIConfigured and .Data.DefaultProvider.
type aiChatData struct {
	baseAdminData
	AIConfigured    bool
	DefaultProvider string
}

// AIChatPage renders GET /admin/ai/chat. AIConfigured reports whether a default
// provider is selected AND its key is stored - we never decrypt here.
func (h *AdminHandlers) AIChatPage(w http.ResponseWriter, r *http.Request) {
	d := aiChatData{baseAdminData: h.base(r, "AI assistant")}
	d.PageDesc = "Chat with your configured AI provider"
	v := h.loadAIView(r.Context())
	d.DefaultProvider = v.DefaultProvider
	for _, p := range v.Providers {
		if p.ID == v.DefaultProvider && p.Configured {
			d.AIConfigured = true
			break
		}
	}
	h.render(w, "ai_chat", d)
}

// chatUserID returns the session user id (== users.id) or 0 when unauthenticated.
func chatUserID(r *http.Request) int64 {
	if sess := middleware.SessionFromContext(r.Context()); sess != nil {
		return sess.UserID
	}
	return 0
}

// AIChatListSessions GET /admin/ai/chat/sessions -> {"sessions":[...]}.
func (h *AdminHandlers) AIChatListSessions(w http.ResponseWriter, r *http.Request) {
	uid := chatUserID(r)
	if uid == 0 || h.ChatStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sessions, err := h.ChatStore.ListSessions(ctx, uid, 100, 0)
	if err != nil {
		h.Logger.Warn("ai chat list sessions", "err", err)
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

// AIChatCreateSession POST /admin/ai/chat/sessions body {"title","provider"} -> {"id"}.
func (h *AdminHandlers) AIChatCreateSession(w http.ResponseWriter, r *http.Request) {
	uid := chatUserID(r)
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
		h.Logger.Warn("ai chat create session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// AIChatGetSession GET /admin/ai/chat/sessions/{id} -> session + messages; 404 if not owned.
func (h *AdminHandlers) AIChatGetSession(w http.ResponseWriter, r *http.Request) {
	uid := chatUserID(r)
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
		h.Logger.Warn("ai chat get session", "err", err)
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

// AIChatDeleteSession DELETE /admin/ai/chat/sessions/{id} -> 204; 404 if not owned.
func (h *AdminHandlers) AIChatDeleteSession(w http.ResponseWriter, r *http.Request) {
	uid := chatUserID(r)
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
		h.Logger.Warn("ai chat delete session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "delete failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AIChatSendMessage POST /admin/ai/chat/sessions/{id}/message streams the reply
// over SSE. It verifies ownership, persists the user turn, replays bounded
// history into the model, streams deltas, then persists the assistant turn.
func (h *AdminHandlers) AIChatSendMessage(w http.ResponseWriter, r *http.Request) {
	uid := chatUserID(r)
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

	// Ownership: GetSession is user-scoped and 404s on a foreign/missing id.
	getCtx, getCancel := context.WithTimeout(r.Context(), 5*time.Second)
	sess, history, err := h.ChatStore.GetSession(getCtx, uid, id)
	getCancel()
	if errors.Is(err, chatstore.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if err != nil {
		h.Logger.Warn("ai chat send: get session", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}

	// Resolve the client BEFORE any streaming so ErrNotConfigured maps to 409.
	clientCtx, clientCancel := context.WithTimeout(r.Context(), 10*time.Second)
	client, err := h.AIFactory.Default(clientCtx)
	clientCancel()
	if err != nil {
		if errors.Is(err, aichat.ErrNotConfigured) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "AI provider not configured"})
			return
		}
		h.Logger.Warn("ai chat send: factory") // never log the error - may carry config detail
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "AI provider unavailable"})
		return
	}

	// Persist the user turn (ownership already verified above).
	persistCtx, persistCancel := context.WithTimeout(r.Context(), 5*time.Second)
	if _, err := h.ChatStore.AppendMessage(persistCtx, id, "user", content); err != nil {
		persistCancel()
		h.Logger.Warn("ai chat send: append user", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "save failed"})
		return
	}
	persistCancel()

	// Build the model input: bounded prior history + this user turn. When tools
	// are available we prepend a system prompt so the model knows it can query
	// live HPG state via the read-only tools.
	// Scope is derived SERVER-SIDE from the session role: super_admin / unscoped
	// admin -> all clients; scoped admin -> assigned clients; client -> own
	// client only; support -> no tools at all. Every tool query is then filtered
	// to that scope so a client can never reach infra or another tenant's data.
	scope, toolsAllowed := h.aiToolScope(r)
	toolsAvailable := h.AITools != nil && providerSupportsTools(client.Provider()) && toolsAllowed
	msgs := buildChatMessages(history, content)
	if toolsAvailable {
		msgs = append([]aichat.Message{{Role: aichat.RoleSystem, Content: aiToolsSystemPrompt}}, msgs...)
	}

	// SSE setup. After this point we only emit SSE frames, never status codes.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived stream; clear absolute deadline

	streamCtx, streamCancel := context.WithCancel(r.Context())
	defer streamCancel()

	var reply string
	var toolsUsed []string
	if toolsAvailable {
		answer, used, err := h.runToolLoop(streamCtx, client, msgs, scope)
		toolsUsed = used
		if err != nil && !errors.Is(err, aichat.ErrToolsUnsupported) {
			h.Logger.Warn("ai chat tool loop", "err", err)
			sseError(w, rc, "stream error")
			return
		}
		if err == nil {
			reply = answer
			if len(reply) > chatAssistantCap {
				reply = reply[:chatAssistantCap]
			}
			// Tool path is non-streaming; emit the final answer as one delta.
			if reply != "" {
				payload, _ := json.Marshal(map[string]string{"text": reply})
				_, _ = w.Write([]byte("data: " + string(payload) + "\n\n"))
				rc.Flush()
			}
		}
		// On ErrToolsUnsupported fall through to plain streaming below.
		if err != nil {
			toolsAvailable = false
		}
	}

	if !toolsAvailable {
		streamed, ok := h.streamReply(streamCtx, w, rc, client, buildChatMessages(history, content))
		if !ok {
			return // client gone or stream error already reported
		}
		reply = streamed
	}

	// Persist the full assistant reply. Use Background so a closed client
	// connection does not abort the write of an already-generated answer.
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	assistantID, serr := h.ChatStore.AppendMessage(saveCtx, id, "assistant", reply)
	saveCancel()
	if serr != nil {
		h.Logger.Warn("ai chat send: append assistant", "err", serr)
		sseError(w, rc, "save failed")
		return
	}
	// Auto-title once the thread has enough turns, derived from the first user
	// message - no upfront prompt. history excludes this turn + the reply just saved.
	if total := len(history) + 2; total >= aiChatAutoTitleAt && (sess.Title == "" || sess.Title == "New chat") {
		if title := firstUserTitle(history, content); title != "" {
			tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = h.ChatStore.UpdateTitle(tctx, uid, id, title)
			tcancel()
		}
	}

	// AI-02: audit every AI tool query (the actions that read tenant data) so a
	// cross-tenant fetch via the assistant leaves a trail. Background ctx: record
	// even if the client already disconnected.
	if len(toolsUsed) > 0 {
		actor := uid
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
		audit.Write(auditCtx, h.DB(), h.Logger, r, audit.Entry{
			UserID: &actor, ActorType: audit.ActorUser,
			Action: "ai.tool_query", Entity: "ai_chat", EntityID: strconv.FormatInt(id, 10),
			Meta: map[string]any{"tools": toolsUsed, "scope": scopeSummary(scope)},
		})
		auditCancel()
	}

	donePayload, _ := json.Marshal(map[string]any{"id": assistantID})
	_, _ = w.Write([]byte("event: done\ndata: " + string(donePayload) + "\n\n"))
	rc.Flush()
}

// scopeSummary renders an AI tool scope for the audit meta: "all" for an
// unscoped admin, otherwise the concrete client-id list the query was bound to.
func scopeSummary(s aitools.Scope) any {
	if s.AllClients {
		return "all"
	}
	return s.ClientIDs
}

// aiChatAutoTitleAt is the combined message count at which a still-default
// session title is auto-derived from the first user turn.
const aiChatAutoTitleAt = 5

// firstUserTitle builds a short single-line title from the first user message
// (falling back to the latest one), truncated on a rune boundary.
func firstUserTitle(history []chatstore.Message, fallback string) string {
	text := fallback
	for _, m := range history {
		if m.Role == "user" && strings.TrimSpace(m.Content) != "" {
			text = m.Content
			break
		}
	}
	text = strings.TrimSpace(strings.ReplaceAll(text, "\n", " "))
	if text == "" {
		return ""
	}
	if r := []rune(text); len(r) > 48 {
		text = strings.TrimSpace(string(r[:48])) + "..."
	}
	return text
}

// aiToolLoopCap bounds tool round-trips so a model cannot loop forever calling
// tools (and burning provider cost) without ever returning a final answer.
const aiToolLoopCap = 5

// aiToolsSystemPrompt tells the model what the read-only tools are for. Kept
// short; the tool schemas carry the per-tool detail.
const aiToolsSystemPrompt = "You are the HPG (Hostyt Proxy Gateway) admin assistant. " +
	"You have read-only tools to inspect live system state (nodes, routes, clients, services, WAF events, traffic). " +
	"CRITICAL RULES: " +
	"(1) NEVER invent, guess, or assume any system state. " +
	"(2) Every factual claim MUST come from a tool call result. " +
	"(3) If no tool covers the question, say you don't have access to that data. " +
	"(4) Do not fabricate alerts, tunnels, backups, or any status not returned by a tool. " +
	"Call tools first, then answer based only on what they returned."

// roleCanUseAITools gates the data-access tools by role. super_admin/admin get
// the full or scoped tool set; client gets a strictly scoped tool set (own
// tenant only). Support is read-only via the allow-list but must NOT reach any
// client/service/traffic data, so it gets NO tools.
func roleCanUseAITools(role string) bool {
	return role == "super_admin" || role == "admin" || role == "client"
}

// aiToolScope derives the caller's tool scope from the session role. The bool is
// false when the caller gets no tools at all (support / unknown / no session).
// The scope is the ONLY source of the client-id filter - model args are never
// trusted. An admin whose AdminScope resolves to a specific client list is
// scoped; an empty scoped list yields no rows (never all).
func (h *AdminHandlers) aiToolScope(r *http.Request) (aitools.Scope, bool) {
	sess := middleware.SessionFromContext(r.Context())
	if sess == nil || !roleCanUseAITools(sess.Role) {
		return aitools.Scope{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	switch sess.Role {
	case "super_admin":
		return aitools.Scope{AllClients: true}, true
	case "admin":
		// Unscoped admin (no AdminScope wired) sees all; scoped admin is limited
		// to assigned clients. An admin with zero assignments sees no client data.
		if h.AdminScope == nil {
			return aitools.Scope{AllClients: true}, true
		}
		ids, all, err := h.AdminScope.ScopeFilter(ctx, sess.UserID)
		if err != nil {
			h.Logger.Warn("ai tool scope: admin scope filter", "err", err)
			return aitools.Scope{}, false
		}
		if all {
			return aitools.Scope{AllClients: true}, true
		}
		return aitools.Scope{ClientIDs: ids}, true
	case "client":
		db := h.DB()
		if db == nil {
			return aitools.Scope{}, false
		}
		cid, err := clientIDFor(ctx, db, sess.UserID)
		if err != nil {
			// No client record -> empty scope -> no rows, but tools still gated.
			return aitools.Scope{ClientIDs: nil}, true
		}
		return aitools.Scope{ClientIDs: []int64{cid}}, true
	default:
		return aitools.Scope{}, false
	}
}

// providerSupportsTools reports whether the provider has a tool-calling adapter.
// Gemini returns ErrToolsUnsupported, so it streams plainly.
func providerSupportsTools(provider string) bool {
	switch provider {
	case "anthropic", "openai", "openrouter":
		return true
	default:
		return false
	}
}

// runToolLoop drives ChatWithTools: execute each requested tool, append the
// results, and call again until the model returns a final text answer or the
// iteration cap is hit. Returns ErrToolsUnsupported when the provider has no
// tool path so the caller can fall back to plain streaming.
func (h *AdminHandlers) runToolLoop(ctx context.Context, client aichat.Client, msgs []aichat.Message, scope aitools.Scope) (string, []string, error) {
	specs := h.AITools.SpecsFor(scope)
	var used []string // AI-02: tool names actually executed, for the audit trail
	for i := 0; i < aiToolLoopCap; i++ {
		turn, err := client.ChatWithTools(ctx, msgs, aichat.Options{Temperature: -1}, specs)
		if err != nil {
			return "", used, err
		}
		if len(turn.ToolCalls) == 0 {
			return turn.Text, used, nil // final answer
		}
		// Record the assistant tool-call turn, then run each tool and feed the
		// results back as RoleTool messages.
		msgs = append(msgs, aichat.Message{Role: aichat.RoleAssistant, Content: turn.Text, ToolCalls: turn.ToolCalls})
		for _, call := range turn.ToolCalls {
			used = append(used, call.Name)
			callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			result, cerr := h.AITools.CallScoped(callCtx, scope, call.Name, call.Arguments)
			cancel()
			if cerr != nil {
				h.Logger.Warn("ai tool call", "tool", call.Name, "err", cerr)
				result = `{"error":"tool execution failed"}`
			}
			msgs = append(msgs, aichat.Message{Role: aichat.RoleTool, ToolCallID: call.ID, Content: result})
		}
	}
	// Cap hit: make one last plain call so the user still gets an answer.
	turn, err := client.ChatWithTools(ctx, msgs, aichat.Options{Temperature: -1}, nil)
	if err != nil {
		return "", used, err
	}
	return turn.Text, used, nil
}

// streamReply runs a plain StreamChat and pumps deltas to the client. It returns
// the buffered reply and false when the client disconnected or an error frame
// was already emitted.
func (h *AdminHandlers) streamReply(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, client aichat.Client, msgs []aichat.Message) (string, bool) {
	ch, err := client.StreamChat(ctx, msgs, aichat.Options{Temperature: -1})
	if err != nil {
		sseError(w, rc, "AI request failed")
		return "", false
	}
	var b strings.Builder
	for chunk := range ch {
		if chunk.Err != nil {
			h.Logger.Warn("ai chat stream", "err", chunk.Err)
			sseError(w, rc, "stream error")
			return "", false
		}
		if chunk.Text != "" && b.Len() < chatAssistantCap {
			b.WriteString(chunk.Text)
			payload, _ := json.Marshal(map[string]string{"text": chunk.Text})
			if _, werr := w.Write([]byte("data: " + string(payload) + "\n\n")); werr != nil {
				return "", false // client gone
			}
			rc.Flush()
		}
		if chunk.Done {
			break
		}
	}
	return b.String(), true
}

// buildChatMessages maps stored history (bounded to the last chatHistoryLimit
// turns) plus the new user message into the provider message slice.
func buildChatMessages(history []chatstore.Message, newUser string) []aichat.Message {
	if len(history) > chatHistoryLimit {
		history = history[len(history)-chatHistoryLimit:]
	}
	msgs := make([]aichat.Message, 0, len(history)+1)
	for _, m := range history {
		role := aichat.Role(m.Role)
		switch role {
		case aichat.RoleSystem, aichat.RoleUser, aichat.RoleAssistant:
		default:
			continue // skip tool/unknown roles the providers do not accept
		}
		msgs = append(msgs, aichat.Message{Role: role, Content: m.Content})
	}
	msgs = append(msgs, aichat.Message{Role: aichat.RoleUser, Content: newUser})
	return msgs
}

// sseError emits a terminal SSE error frame. msg must be a fixed, secret-free
// string - never an upstream error that could carry the API key.
func sseError(w http.ResponseWriter, rc *http.ResponseController, msg string) {
	payload, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write([]byte("event: error\ndata: " + string(payload) + "\n\n"))
	rc.Flush()
}
