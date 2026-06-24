package view

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed status/*.html.tmpl
var statusFS embed.FS

// StatusTemplates holds the compiled public status page templates.
type StatusTemplates struct {
	t *template.Template
}

// LoadStatusTemplates parses the status/ template directory.
func LoadStatusTemplates() (*StatusTemplates, error) {
	fm := CommonFuncs()
	// humanBytes is duplicated here to avoid an import cycle with handlers.
	fm["humanBytes"] = func(n uint64) string {
		switch {
		case n < 1024:
			return fmt.Sprintf("%d B", n)
		case n < 1024*1024:
			return fmt.Sprintf("%.1f KB", float64(n)/1024)
		case n < 1024*1024*1024:
			return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
		default:
			return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
		}
	}
	t, err := template.New("").Funcs(fm).ParseFS(statusFS, "status/*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse status templates: %w", err)
	}
	return &StatusTemplates{t: t}, nil
}

// Render executes the named status page template.
func (st *StatusTemplates) Render(w io.Writer, page string, data any) error {
	return st.t.ExecuteTemplate(w, page+".html.tmpl", data)
}
