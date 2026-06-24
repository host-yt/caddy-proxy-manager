package view

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed install/*.html.tmpl install/_layout.html.tmpl
var installFS embed.FS

// InstallTemplates is a name->template map keyed by step name.
type InstallTemplates struct {
	t *template.Template
}

func LoadInstallTemplates() (*InstallTemplates, error) {
	t, err := template.New("").Funcs(CommonFuncs()).ParseFS(installFS,
		"install/_layout.html.tmpl",
		"install/*.html.tmpl",
	)
	if err != nil {
		return nil, fmt.Errorf("parse install templates: %w", err)
	}
	return &InstallTemplates{t: t}, nil
}

// Render writes the named step template inside the layout.
func (it *InstallTemplates) Render(w io.Writer, step string, data any) error {
	return it.t.ExecuteTemplate(w, "layout.html.tmpl", map[string]any{
		"Step": step,
		"Data": data,
	})
}
