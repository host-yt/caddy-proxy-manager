package routes

import (
	"context"
	"errors"
	"testing"
)

// Every create path funnels through Create - the NPM import builds both values
// out of an uploaded file - so the placeholder screen belongs here, not in the
// panel form. No DB is touched: the refusal happens before the first query.
func TestCreateRefusesUnsafePlaceholders(t *testing.T) {
	cases := []struct {
		name string
		in   CreateInput
	}{
		{"redirect url", CreateInput{Domain: "a.example", Kind: "redirect", RedirectURL: "https://x/{env.DB_PASSWORD}"}},
		{"upstream host header", CreateInput{Domain: "a.example", UpstreamHostHeader: " {file./etc/passwd} "}},
	}
	for _, c := range cases {
		if _, err := (&Service{}).Create(context.Background(), 1, c.in); !errors.Is(err, ErrUnsafePlaceholder) {
			t.Errorf("%s: want ErrUnsafePlaceholder, got %v", c.name, err)
		}
	}
}
