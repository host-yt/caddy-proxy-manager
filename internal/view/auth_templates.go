package view

import (
	"embed"
	"fmt"
	"html/template"
	"io"
)

//go:embed auth/*.html.tmpl
var authFS embed.FS

type AuthTemplates struct {
	t *template.Template
}

func LoadAuthTemplates() (*AuthTemplates, error) {
	t, err := template.New("").Funcs(CommonFuncs()).ParseFS(authFS, "auth/*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse auth templates: %w", err)
	}
	return &AuthTemplates{t: t}, nil
}

func (at *AuthTemplates) Render(w io.Writer, name string, data any) error {
	return at.t.ExecuteTemplate(w, name, data)
}
