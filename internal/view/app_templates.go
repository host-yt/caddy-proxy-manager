package view

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed app/*.html.tmpl
var appFS embed.FS

type AppTemplates struct {
	t *template.Template
}

func LoadAppTemplates() (*AppTemplates, error) {
	t, err := template.New("").Funcs(CommonFuncs()).ParseFS(appFS, "app/*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse app templates: %w", err)
	}
	return &AppTemplates{t: t}, nil
}

func (at *AppTemplates) Render(w io.Writer, page string, data any) error {
	return at.t.ExecuteTemplate(w, "layout.html.tmpl", map[string]any{
		"Page": page,
		"Data": data,
	})
}
