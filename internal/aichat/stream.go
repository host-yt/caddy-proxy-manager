package aichat

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// defaultMaxTokens is used when Options.MaxTokens <= 0.
const defaultMaxTokens = 1024

// maxToks resolves the effective max-tokens for a call.
func maxToks(o Options) int {
	if o.MaxTokens > 0 {
		return o.MaxTokens
	}
	return defaultMaxTokens
}

// doStream issues req and hands the response body line-by-line to onLine. It
// owns channel lifecycle: a goroutine runs the SSE pump and the returned
// channel always closes. parseLine extracts assistant text from one SSE
// "data:" payload; returning ("", true, nil) means the stream is finished.
//
// req must already carry auth + body. The HTTP call happens inside the
// goroutine so StreamChat returns immediately and ctx cancellation is honored.
func doStream(
	ctx context.Context,
	req *http.Request,
	parseLine func(data string) (text string, done bool, err error),
) (<-chan Chunk, error) {
	out := make(chan Chunk, 16)
	go func() {
		defer close(out)
		resp, err := httpClient.Do(req)
		if err != nil {
			emit(ctx, out, Chunk{Err: fmt.Errorf("aichat: request failed: %w", err)})
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			emit(ctx, out, Chunk{Err: statusErr(resp)})
			return
		}
		sc := bufio.NewScanner(resp.Body)
		// Allow long SSE lines (some providers pack big JSON deltas).
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := strings.TrimSpace(sc.Text())
			if line == "" || !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data == "[DONE]" { // OpenAI-style terminator
				emit(ctx, out, Chunk{Done: true})
				return
			}
			text, done, perr := parseLine(data)
			if perr != nil {
				emit(ctx, out, Chunk{Err: perr})
				return
			}
			if text != "" {
				if !emit(ctx, out, Chunk{Text: text}) {
					return
				}
			}
			if done {
				emit(ctx, out, Chunk{Done: true})
				return
			}
		}
		if err := sc.Err(); err != nil && ctx.Err() == nil {
			emit(ctx, out, Chunk{Err: fmt.Errorf("aichat: stream read: %w", err)})
			return
		}
		emit(ctx, out, Chunk{Done: true})
	}()
	return out, nil
}

// emit sends c unless ctx is done. Returns false when the caller cancelled.
func emit(ctx context.Context, out chan<- Chunk, c Chunk) bool {
	select {
	case out <- c:
		return true
	case <-ctx.Done():
		return false
	}
}

// doVerify issues a non-streaming request and returns nil on 2xx. Used by the
// Settings "Test" button. The body is read+discarded; only status decides
// success so we never echo the key or sensitive payload.
func doVerify(req *http.Request) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("aichat: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusErr(resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// doJSON issues a non-streaming request and decodes a 2xx JSON body into out.
// Used by the tool-calling path. The body is size-capped so a hostile/oversized
// response cannot exhaust memory. Errors never echo the key or request headers.
func doJSON(req *http.Request, out any) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("aichat: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusErr(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return fmt.Errorf("aichat: read response: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("aichat: decode response: %w", err)
	}
	return nil
}

// statusErr builds a terminal error from a non-2xx response without leaking
// request headers/keys. The body usually carries a provider error message.
func statusErr(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("aichat: provider returned status %d", resp.StatusCode)
	}
	return fmt.Errorf("aichat: provider status %d: %s", resp.StatusCode, msg)
}
