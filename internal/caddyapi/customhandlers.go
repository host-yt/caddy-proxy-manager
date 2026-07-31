package caddyapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
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

// handlerSchemas type-check each allow-listed handler against the Caddy
// v2.11.1 module structs. A permitted NAME carrying a value Caddy cannot
// unmarshal (or an encoder the node image lacks) fails the whole /load, which
// would leave routing stale or the node down - so it must never be emitted.
var handlerSchemas = map[string]func(map[string]any) error{
	"headers":      validateHeadersHandler,
	"encode":       validateEncodeHandler,
	"rewrite":      validateRewriteHandler,
	"vars":         validateVarsHandler,
	"request_body": validateRequestBodyHandler,
}

// nodeEncoders are the http.encoders modules the node image actually builds
// (deploy/caddy/Dockerfile adds none); an unknown one aborts provisioning.
var nodeEncoders = map[string]bool{"gzip": true, "zstd": true}

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

// --- strict per-handler schemas (Caddy v2.11.1 module structs) ---

func asObject(v any, where string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", where)
	}
	return m, nil
}

func onlyKeys(m map[string]any, allowed map[string]bool, where string) error {
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("%s: key %q is not permitted", where, k)
		}
	}
	return nil
}

func wantString(v any, where string) error {
	if _, ok := v.(string); !ok {
		return fmt.Errorf("%s must be a string", where)
	}
	return nil
}

// wantInt enforces a whole number: Caddy's int/int64 fields reject fractions
// and any JSON string outright.
func wantInt(v any, where string) error {
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || math.IsInf(f, 0) {
		return fmt.Errorf("%s must be an integer", where)
	}
	return nil
}

func wantStringSlice(v any, where string) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", where)
	}
	out := make([]string, 0, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", where, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// wantHeaderMap matches Go's http.Header: object of string -> array of strings.
func wantHeaderMap(v any, where string) error {
	m, err := asObject(v, where)
	if err != nil {
		return err
	}
	for k, vv := range m {
		if _, err := wantStringSlice(vv, where+"."+k); err != nil {
			return err
		}
	}
	return nil
}

// compilableRegexp mirrors Caddy: patterns holding a placeholder are compiled
// at request time, everything else must compile at provision time.
func compilableRegexp(pat, where string) error {
	if i := strings.Index(pat, "{"); i >= 0 && strings.Index(pat[i+1:], "}") > 0 {
		return nil
	}
	if _, err := regexp.Compile(pat); err != nil {
		return fmt.Errorf("%s is not a valid regular expression: %v", where, err)
	}
	return nil
}

var headerOpsKeys = map[string]bool{"add": true, "set": true, "delete": true, "replace": true}
var respHeaderOpsKeys = map[string]bool{"add": true, "set": true, "delete": true,
	"replace": true, "require": true, "deferred": true}

func validateHeaderOps(v any, resp bool, where string) error {
	m, err := asObject(v, where)
	if err != nil {
		return err
	}
	keys := headerOpsKeys
	if resp {
		keys = respHeaderOpsKeys
	}
	if err := onlyKeys(m, keys, where); err != nil {
		return err
	}
	for k, vv := range m {
		sub := where + "." + k
		switch k {
		case "add", "set":
			if err := wantHeaderMap(vv, sub); err != nil {
				return err
			}
		case "delete":
			if _, err := wantStringSlice(vv, sub); err != nil {
				return err
			}
		case "replace":
			rm, err := asObject(vv, sub)
			if err != nil {
				return err
			}
			for field, reps := range rm {
				arr, ok := reps.([]any)
				if !ok {
					return fmt.Errorf("%s.%s must be an array of replacements", sub, field)
				}
				for i, e := range arr {
					rw := fmt.Sprintf("%s.%s[%d]", sub, field, i)
					ro, err := asObject(e, rw)
					if err != nil {
						return err
					}
					if err := onlyKeys(ro, map[string]bool{
						"search": true, "search_regexp": true, "replace": true}, rw); err != nil {
						return err
					}
					for rk, rv := range ro {
						if err := wantString(rv, rw+"."+rk); err != nil {
							return err
						}
						if rk == "search_regexp" {
							if err := compilableRegexp(rv.(string), rw+".search_regexp"); err != nil {
								return err
							}
						}
					}
				}
			}
		case "deferred":
			if _, ok := vv.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", sub)
			}
		case "require":
			rm, err := asObject(vv, sub)
			if err != nil {
				return err
			}
			if err := onlyKeys(rm, map[string]bool{"status_code": true, "headers": true}, sub); err != nil {
				return err
			}
			if codes, ok := rm["status_code"]; ok {
				arr, ok := codes.([]any)
				if !ok {
					return fmt.Errorf("%s.status_code must be an array of integers", sub)
				}
				for i, c := range arr {
					if err := wantInt(c, fmt.Sprintf("%s.status_code[%d]", sub, i)); err != nil {
						return err
					}
				}
			}
			if hdrs, ok := rm["headers"]; ok {
				if err := wantHeaderMap(hdrs, sub+".headers"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateHeadersHandler(h map[string]any) error {
	if v, ok := h["request"]; ok {
		if err := validateHeaderOps(v, false, "request"); err != nil {
			return err
		}
	}
	if v, ok := h["response"]; ok {
		if err := validateHeaderOps(v, true, "response"); err != nil {
			return err
		}
	}
	return nil
}

func validateEncodeHandler(h map[string]any) error {
	if v, ok := h["encodings"]; ok {
		m, err := asObject(v, "encodings")
		if err != nil {
			return err
		}
		for name, cfg := range m {
			if !nodeEncoders[name] {
				return fmt.Errorf("encodings: encoder %q is not installed on the node", name)
			}
			c, err := asObject(cfg, "encodings."+name)
			if err != nil {
				return err
			}
			if err := onlyKeys(c, map[string]bool{"level": true}, "encodings."+name); err != nil {
				return err
			}
			if lvl, ok := c["level"]; ok {
				// gzip level is an int, zstd level is a named string.
				if name == "gzip" {
					if err := wantInt(lvl, "encodings.gzip.level"); err != nil {
						return err
					}
				} else if err := wantString(lvl, "encodings.zstd.level"); err != nil {
					return err
				}
			}
		}
	}
	if v, ok := h["prefer"]; ok {
		names, err := wantStringSlice(v, "prefer")
		if err != nil {
			return err
		}
		for _, n := range names {
			if !nodeEncoders[n] {
				return fmt.Errorf("prefer: encoder %q is not installed on the node", n)
			}
		}
	}
	if v, ok := h["minimum_length"]; ok {
		if err := wantInt(v, "minimum_length"); err != nil {
			return err
		}
	}
	return nil
}

func validateRewriteHandler(h map[string]any) error {
	for _, k := range []string{"method", "uri", "strip_path_prefix", "strip_path_suffix"} {
		if v, ok := h[k]; ok {
			if err := wantString(v, k); err != nil {
				return err
			}
		}
	}
	if v, ok := h["uri_substring"]; ok {
		arr, ok := v.([]any)
		if !ok {
			return errors.New("uri_substring must be an array of objects")
		}
		for i, e := range arr {
			where := fmt.Sprintf("uri_substring[%d]", i)
			o, err := asObject(e, where)
			if err != nil {
				return err
			}
			if err := onlyKeys(o, map[string]bool{"find": true, "replace": true, "limit": true}, where); err != nil {
				return err
			}
			for k, vv := range o {
				if k == "limit" {
					if err := wantInt(vv, where+".limit"); err != nil {
						return err
					}
				} else if err := wantString(vv, where+"."+k); err != nil {
					return err
				}
			}
		}
	}
	if v, ok := h["path_regexp"]; ok {
		arr, ok := v.([]any)
		if !ok {
			return errors.New("path_regexp must be an array of objects")
		}
		for i, e := range arr {
			where := fmt.Sprintf("path_regexp[%d]", i)
			o, err := asObject(e, where)
			if err != nil {
				return err
			}
			if err := onlyKeys(o, map[string]bool{"find": true, "replace": true}, where); err != nil {
				return err
			}
			for k, vv := range o {
				if err := wantString(vv, where+"."+k); err != nil {
					return err
				}
			}
			// Caddy's Provision rejects an empty or uncompilable find outright.
			find, _ := o["find"].(string)
			if find == "" {
				return fmt.Errorf("%s.find cannot be empty", where)
			}
			if err := compilableRegexp(find, where+".find"); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateVarsHandler: free-form variable names, scalar values only - a nested
// value would carry structure the allow-list cannot reason about.
func validateVarsHandler(h map[string]any) error {
	for k, v := range h {
		if k == "handler" {
			continue
		}
		switch v.(type) {
		case map[string]any, []any:
			return fmt.Errorf("%q must be a scalar value", k)
		}
	}
	return nil
}

// validateRequestBodyHandler: the timeouts are plain time.Duration in Caddy,
// so they unmarshal from nanosecond integers only - "30s" breaks the load.
func validateRequestBodyHandler(h map[string]any) error {
	for _, k := range []string{"max_size", "read_timeout", "write_timeout"} {
		if v, ok := h[k]; ok {
			if err := wantInt(v, k); err != nil {
				return err
			}
		}
	}
	return nil
}

// SanitizeCustomHandlers validates and re-marshals an admin-supplied JSON array
// of Caddy handler objects against customHandlerProps plus a strict per-handler
// type schema. Allow-list, not deny-list: an unknown handler, property or value
// type is rejected. 16 KiB hard cap. Empty input is OK. Called on write AND at
// emission time, so a chain stored before this policy existed can never reach a
// node - a route carrying one is quarantined (see CustomHandlerQuarantine).
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
			if err := rejectNestedHandlers(v, 0); err != nil {
				return "", fmt.Errorf("entry #%d: %q: %v", i, k, err)
			}
			if err := rejectUnsafePlaceholders(v, 0); err != nil {
				return "", fmt.Errorf("entry #%d: %q: %v", i, k, err)
			}
		}
		// Types last: names alone do not make a chain loadable by Caddy.
		if schema := handlerSchemas[name]; schema != nil {
			if err := schema(h); err != nil {
				return "", fmt.Errorf("entry #%d: handler %q: %v", i, name, err)
			}
		} else {
			return "", fmt.Errorf("entry #%d: handler %q has no schema", i, name)
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
