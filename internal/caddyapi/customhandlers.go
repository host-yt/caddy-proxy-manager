package caddyapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// customHandlerProps is the ALLOW-LIST of admin-supplied Caddy handlers and the
// properties each may carry. Request/response shaping only: a handler able to
// proxy, route, authenticate, execute or read the filesystem would hand the
// route owner the node itself (reverse_proxy to Caddy's local admin API is a
// full takeover). Names deliberately mirror cacheSafeCustomHandlers.
//
// `templates` is deliberately absent: Caddy's template FuncMap ships env,
// readFile, httpInclude and placeholder with no sandbox, and the chain runs
// around a tenant-controlled upstream response.
var customHandlerProps = map[string]map[string]bool{
	"headers": {"request": true, "response": true},
	"encode":  {"encodings": true, "prefer": true, "minimum_length": true},
	"rewrite": {"method": true, "uri": true, "strip_path_prefix": true,
		"strip_path_suffix": true, "uri_substring": true, "path_regexp": true},
	"vars":         nil, // free-form keys; scalar values only (checked below)
	"request_body": {"max_size": true, "read_timeout": true, "write_timeout": true},
}

// nestedHandlerKeys embed further handlers/routes. The flat allow-list does not
// walk them, so their presence anywhere below the top level is fatal.
var nestedHandlerKeys = map[string]bool{
	"handler": true, "handle": true, "routes": true, "handler_chain": true,
	"error_routes": true, "match": true, "terminal": true, "group": true,
}

// unsafePlaceholderTokens are Caddy replacer namespaces that read the node's
// environment or filesystem. Header values and rewrite URIs are expanded by the
// replacer, so a route owner could otherwise exfiltrate node secrets.
var unsafePlaceholderTokens = []string{"{env.", "{file.", "{system.", "{$"}

// rejectNestedHandlers walks a handler property and refuses any embedded
// handler/route object, which would smuggle a denied capability past the
// flat allow-list.
func rejectNestedHandlers(v any, depth int) error {
	if depth > 8 {
		return errors.New("nested too deeply")
	}
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			if nestedHandlerKeys[k] {
				return fmt.Errorf("nested %q is not permitted", k)
			}
			if err := rejectNestedHandlers(vv, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, vv := range t {
			if err := rejectNestedHandlers(vv, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectUnsafePlaceholders walks every string (keys included) below a handler
// property and refuses env/file/system placeholders wherever they hide.
func rejectUnsafePlaceholders(v any, depth int) error {
	if depth > 8 {
		return errors.New("nested too deeply")
	}
	switch t := v.(type) {
	case string:
		low := strings.ToLower(t)
		for _, tok := range unsafePlaceholderTokens {
			if strings.Contains(low, tok) {
				return fmt.Errorf("placeholder %q is not permitted", tok+"...}")
			}
		}
	case map[string]any:
		for k, vv := range t {
			if err := rejectUnsafePlaceholders(k, depth+1); err != nil {
				return err
			}
			if err := rejectUnsafePlaceholders(vv, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, vv := range t {
			if err := rejectUnsafePlaceholders(vv, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// SanitizeCustomHandlers validates and re-marshals an admin-supplied JSON array
// of Caddy handler objects against customHandlerProps. Allow-list, not
// deny-list: an unknown handler or property is rejected. 16 KiB hard cap.
// Empty input is OK. Called on write AND at emission time, so a chain stored
// before this policy existed can never reach a node.
func SanitizeCustomHandlers(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 16384 {
		return "", fmt.Errorf("too large (16 KiB max)")
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		return "", fmt.Errorf("must be a JSON array of objects: %v", err)
	}
	for i, h := range arr {
		name, _ := h["handler"].(string)
		if name == "" {
			return "", fmt.Errorf("entry #%d missing required `handler` key", i)
		}
		props, allowed := customHandlerProps[name]
		if !allowed {
			return "", fmt.Errorf("entry #%d: handler %q is not permitted", i, name)
		}
		for k, v := range h {
			if k == "handler" {
				continue
			}
			if props != nil && !props[k] {
				return "", fmt.Errorf("entry #%d: property %q is not permitted on handler %q", i, k, name)
			}
			if props == nil {
				// vars: free-form names, so only scalars are safe to accept.
				switch v.(type) {
				case map[string]any, []any:
					return "", fmt.Errorf("entry #%d: %q must be a scalar value", i, k)
				}
			}
			if err := rejectNestedHandlers(v, 0); err != nil {
				return "", fmt.Errorf("entry #%d: %q: %v", i, k, err)
			}
			if err := rejectUnsafePlaceholders(v, 0); err != nil {
				return "", fmt.Errorf("entry #%d: %q: %v", i, k, err)
			}
		}
	}
	// Re-marshal so we store a normalised form (and reject sneaky
	// whitespace-only or BOM-prefixed inputs).
	out, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("re-marshal failed: %v", err)
	}
	return string(out), nil
}
