// Package customfields manages admin-defined custom fields per entity type.
package customfields

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// FieldType is the data type of a custom field.
type FieldType string

const (
	Text   FieldType = "text"
	Number FieldType = "number"
	Select FieldType = "select"
	Bool   FieldType = "bool"
)

// Def is a single custom field definition loaded from custom_field_defs.
type Def struct {
	ID         int64
	EntityType string
	Key        string
	Label      string
	Type       FieldType
	Options    []string
	Required   bool
	Sort       int
}

// View is a Def joined with its current value, for templates.
type View struct {
	Def   Def
	Value string
}

var slugRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// ValidateKey checks that k is a valid field_key slug.
func ValidateKey(k string) bool { return slugRE.MatchString(k) }

// ValidateFieldType returns true for known field types.
func ValidateFieldType(t FieldType) bool {
	switch t {
	case Text, Number, Select, Bool:
		return true
	}
	return false
}

// LoadDefs returns defs for an entity_type ordered by sort_order, id.
func LoadDefs(ctx context.Context, db *sql.DB, entityType string) ([]Def, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, entity_type, field_key, label, field_type, options_json, required, sort_order
		   FROM custom_field_defs WHERE entity_type = ? ORDER BY sort_order ASC, id ASC`,
		entityType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var defs []Def
	for rows.Next() {
		var d Def
		var optJSON sql.NullString
		var req int
		if err := rows.Scan(&d.ID, &d.EntityType, &d.Key, &d.Label, &d.Type,
			&optJSON, &req, &d.Sort); err != nil {
			return nil, err
		}
		d.Required = req == 1
		if optJSON.Valid && optJSON.String != "" {
			_ = json.Unmarshal([]byte(optJSON.String), &d.Options)
		}
		defs = append(defs, d)
	}
	return defs, rows.Err()
}

// Decode parses a stored custom_fields JSON string into key->value.
// Nil-safe: "" returns an empty map.
func Decode(jsonStr string) map[string]string {
	if jsonStr == "" {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return map[string]string{}
	}
	return m
}

// EncodeFromForm reads form values for the given defs (form key = "cf_"+def.Key),
// validates them, and returns the JSON string to store. Returns (json, validationError).
func EncodeFromForm(defs []Def, form url.Values) (string, error) {
	out := make(map[string]string, len(defs))
	for _, d := range defs {
		raw := strings.TrimSpace(form.Get("cf_" + d.Key))
		switch d.Type {
		case Text:
			if d.Required && raw == "" {
				return "", fmt.Errorf("field %q is required", d.Label)
			}
			if len(raw) > 1000 {
				return "", fmt.Errorf("field %q exceeds 1000 characters", d.Label)
			}
		case Number:
			if d.Required && raw == "" {
				return "", fmt.Errorf("field %q is required", d.Label)
			}
			if raw != "" {
				if _, err := strconv.ParseFloat(raw, 64); err != nil {
					return "", fmt.Errorf("field %q must be a number", d.Label)
				}
			}
		case Select:
			if d.Required && raw == "" {
				return "", fmt.Errorf("field %q is required", d.Label)
			}
			if raw != "" {
				valid := false
				for _, opt := range d.Options {
					if opt == raw {
						valid = true
						break
					}
				}
				if !valid {
					return "", fmt.Errorf("field %q has an invalid selection", d.Label)
				}
			}
		case Bool:
			// Checkbox: "1" when checked, "" when unchecked - no required check
			if raw != "" && raw != "1" {
				raw = ""
			}
		}
		out[d.Key] = raw
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Merge joins defs with their current values for template rendering.
func Merge(defs []Def, values map[string]string) []View {
	views := make([]View, 0, len(defs))
	for _, d := range defs {
		views = append(views, View{Def: d, Value: values[d.Key]})
	}
	return views
}
