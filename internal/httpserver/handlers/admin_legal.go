package handlers

import (
	"context"
	"net/http"
	"time"
)

type legalDoc struct {
	Slug      string
	Title     string
	Body      string
	UpdatedAt string
}

type legalData struct {
	baseAdminData
	Docs []legalDoc
}

// LegalDocsPage GET /admin/legal — list editor.
func (h *AdminHandlers) LegalDocsPage(w http.ResponseWriter, r *http.Request) {
	d := legalData{baseAdminData: h.base(r, "Legal documents")}
	db := h.DB()
	if db == nil {
		h.render(w, "legal", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT slug, title, body, DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i')
		 FROM legal_documents ORDER BY slug`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var doc legalDoc
			if err := rows.Scan(&doc.Slug, &doc.Title, &doc.Body, &doc.UpdatedAt); err == nil {
				d.Docs = append(d.Docs, doc)
			}
		}
	}
	// Seed defaults visually if both standard slugs are missing.
	have := map[string]bool{}
	for _, x := range d.Docs {
		have[x.Slug] = true
	}
	if !have["tos"] {
		d.Docs = append(d.Docs, legalDoc{Slug: "tos", Title: "Terms of Service", Body: ""})
	}
	if !have["privacy"] {
		d.Docs = append(d.Docs, legalDoc{Slug: "privacy", Title: "Privacy Policy", Body: ""})
	}
	h.render(w, "legal", d)
}
