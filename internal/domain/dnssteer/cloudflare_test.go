package dnssteer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareGetRecords_FollowsPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/zones/") {
			page := r.URL.Query().Get("page")
			fmt.Fprintf(w, `{"success":true,"result_info":{"total_pages":2},"result":[{"id":"r%s","type":"A","name":"app.example.com","content":"10.0.0.%s"}]}`, page, page)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[{"id":"z1"}]}`)
	}))
	defer srv.Close()
	old := cfAPIBase
	cfAPIBase = srv.URL
	t.Cleanup(func() { cfAPIBase = old })

	p, err := newCloudflareProvider(map[string]string{"api_token": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := p.GetRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[1].ID != "r2" {
		t.Fatalf("want records from both pages, got %+v", recs)
	}
}
