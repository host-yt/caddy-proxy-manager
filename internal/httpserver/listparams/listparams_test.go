package listparams

import (
	"net/url"
	"testing"
)

func TestParseURL_defaults(t *testing.T) {
	p := ParseURL(url.Values{}, []string{"name", "created_at"}, Defaults{Sort: "created_at", Dir: "desc", Size: 25})
	if p.Page != 1 {
		t.Errorf("page want 1, got %d", p.Page)
	}
	if p.Size != 25 {
		t.Errorf("size want 25, got %d", p.Size)
	}
	if p.Sort != "created_at" {
		t.Errorf("sort want created_at, got %s", p.Sort)
	}
	if p.Dir != "desc" {
		t.Errorf("dir want desc, got %s", p.Dir)
	}
}

func TestParseURL_clampSize(t *testing.T) {
	q := url.Values{"size": {"9999"}}
	p := ParseURL(q, nil, Defaults{Size: 50})
	if p.Size != maxSize {
		t.Errorf("want %d, got %d", maxSize, p.Size)
	}
}

func TestParseURL_rejectInjection(t *testing.T) {
	q := url.Values{"sort": {"id; DROP TABLE users--"}}
	p := ParseURL(q, []string{"name", "created_at"}, Defaults{Sort: "created_at", Dir: "desc"})
	// injection attempt must be rejected and fall back to default
	if p.Sort != "created_at" {
		t.Errorf("injection not blocked, sort=%q", p.Sort)
	}
}

func TestParseURL_validSort(t *testing.T) {
	q := url.Values{"sort": {"name"}, "dir": {"asc"}}
	p := ParseURL(q, []string{"name", "created_at"}, Defaults{Sort: "created_at", Dir: "desc"})
	if p.Sort != "name" || p.Dir != "asc" {
		t.Errorf("want name/asc, got %s/%s", p.Sort, p.Dir)
	}
}

func TestParseURL_invalidDir(t *testing.T) {
	q := url.Values{"dir": {"DROP"}}
	p := ParseURL(q, nil, Defaults{Dir: "asc"})
	if p.Dir != "asc" {
		t.Errorf("want asc, got %s", p.Dir)
	}
}

func TestOffset(t *testing.T) {
	p := Params{Page: 3, Size: 25}
	if got := p.Offset(); got != 50 {
		t.Errorf("offset want 50, got %d", got)
	}
}

func TestOrderBySQL(t *testing.T) {
	p := Params{Sort: "name", Dir: "asc"}
	want := "name ASC"
	if got := p.OrderBySQL("id"); got != want {
		t.Errorf("want %q got %q", want, got)
	}
}

func TestOrderBySQL_fallback(t *testing.T) {
	p := Params{Sort: "", Dir: "desc"}
	want := "id DESC"
	if got := p.OrderBySQL("id"); got != want {
		t.Errorf("want %q got %q", want, got)
	}
}

func TestNewPageInfo(t *testing.T) {
	p := Params{Page: 2, Size: 10}
	pi := NewPageInfo(p, 35)
	if pi.TotalPgs != 4 {
		t.Errorf("total pages want 4, got %d", pi.TotalPgs)
	}
	if !pi.HasPrev || !pi.HasNext {
		t.Errorf("want HasPrev+HasNext on page 2 of 4")
	}
	if pi.PrevPage != 1 || pi.NextPage != 3 {
		t.Errorf("prev/next wrong: %d/%d", pi.PrevPage, pi.NextPage)
	}
}

func TestBuildURL(t *testing.T) {
	base := url.Values{"page": {"1"}, "q": {"foo"}}
	got := BuildURL(base, map[string]string{"page": "2"})
	if got == "" {
		t.Fatal("empty url")
	}
	parsed, _ := url.ParseQuery(got[1:]) // strip leading "?"
	if parsed.Get("page") != "2" {
		t.Errorf("page not overridden: %s", got)
	}
	if parsed.Get("q") != "foo" {
		t.Errorf("q not preserved: %s", got)
	}
}

func TestSortURL_toggle(t *testing.T) {
	base := url.Values{}
	url1 := SortURL(base, "name", "", "desc")
	parsed1, _ := url.ParseQuery(url1[1:])
	if parsed1.Get("dir") != "asc" {
		t.Errorf("first click should be asc, got %s", parsed1.Get("dir"))
	}
	url2 := SortURL(base, "name", "name", "asc")
	parsed2, _ := url.ParseQuery(url2[1:])
	if parsed2.Get("dir") != "desc" {
		t.Errorf("second click should toggle to desc, got %s", parsed2.Get("dir"))
	}
}
