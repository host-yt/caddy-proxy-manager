package view

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/i18n"
)

//go:embed admin/*.html.tmpl
var adminFS embed.FS

type AdminTemplates struct {
	t *template.Template
}

// CommonFuncs returns template helper funcs shared by every template set:
//
//	T(lang, key)   → i18n.T (returns key when not translated)
//	nonceAttr      → emits ` nonce="<n>"` or "" - useful for conditional
//	                 third-party script tags that we don't want to mark
//	                 when the nonce is missing.
func CommonFuncs() template.FuncMap {
	return template.FuncMap{
		"T": i18n.T,
		"nonceAttr": func(n string) template.HTMLAttr {
			if n == "" {
				return ""
			}
			return template.HTMLAttr(` nonce="` + n + `"`)
		},
		// firstRune is rune-safe (slice 0 1 breaks on multibyte actors).
		"firstRune": func(s string) string {
			r := []rune(strings.TrimSpace(s))
			if len(r) == 0 {
				return "?"
			}
			return strings.ToUpper(string(r[0]))
		},
		// dict builds a map from k,v pairs so a partial can receive multiple
		// named values: {{template "host_row" (dict "Row" . "CSRF" $.CSRF)}}.
		"dict": func(kv ...any) (map[string]any, error) {
			if len(kv)%2 != 0 {
				return nil, fmt.Errorf("dict: odd arg count")
			}
			m := make(map[string]any, len(kv)/2)
			for i := 0; i < len(kv); i += 2 {
				k, ok := kv[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict: non-string key")
				}
				m[k] = kv[i+1]
			}
			return m, nil
		},
		"slice":    func(v ...any) []any { return v },
		// splitStr splits a string by sep; used to render scope pills in templates.
		"splitStr": strings.Split,
		// trimStr trims whitespace from a string; used alongside splitStr.
		"trimStr": strings.TrimSpace,
		// divf divides two int64 values and returns float64; used for byte formatting.
		"divf": func(a, b int64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		// mulf multiplies two float64 values; used to format percentages.
		"mulf": func(a, b float64) float64 { return a * b },
		// formatBytes converts a byte count to a human-readable string.
		"formatBytes": func(n int64) string {
			if n == 0 {
				return "0 B"
			}
			if n < 1024 {
				return fmt.Sprintf("%d B", n)
			}
			if n < 1024*1024 {
				return fmt.Sprintf("%.1f KB", float64(n)/1024)
			}
			if n < 1024*1024*1024 {
				return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
			}
			return fmt.Sprintf("%.2f GB", float64(n)/1024/1024/1024)
		},
	}
}

func LoadAdminTemplates() (*AdminTemplates, error) {
	t, err := template.New("").Funcs(CommonFuncs()).ParseFS(adminFS, "admin/*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse admin templates: %w", err)
	}
	return &AdminTemplates{t: t}, nil
}

// Render runs `layout.html.tmpl` with the named page partial injected.
func (at *AdminTemplates) Render(w io.Writer, page string, data any) error {
	return at.t.ExecuteTemplate(w, "layout.html.tmpl", map[string]any{
		"Page": page,
		"Data": data,
	})
}
