package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Issue redirects (303) and the one-time bundle is shown on the next GET only.
func TestMTLSBundlePRG(t *testing.T) {
	h := &AdminHandlers{}
	rec := httptest.NewRecorder()
	h.redirectMTLSBundle(rec, httptest.NewRequest("POST", "/admin/mtls/ca/1/issue", nil),
		mtlsBundle{Subject: "s", Serial: "1", CertPEM: "-----BEGIN CERTIFICATE-----\nx\n", KeyPEM: "k\n"})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	get := httptest.NewRequest("GET", "/admin/mtls", nil)
	for _, c := range rec.Result().Cookies() {
		get.AddCookie(c)
	}
	if b := h.takeMTLSBundle(httptest.NewRecorder(), get); b == nil || b.KeyPEM != "k\n" {
		t.Fatalf("first GET must show bundle, got %+v", b)
	}
	if b := h.takeMTLSBundle(httptest.NewRecorder(), httptest.NewRequest("GET", "/admin/mtls", nil)); b != nil {
		t.Fatal("second GET must not show bundle")
	}
}
