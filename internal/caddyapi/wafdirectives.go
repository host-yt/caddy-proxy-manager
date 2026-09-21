package caddyapi

import (
	"fmt"
	"strconv"
	"strings"
)

// WAF directives are concatenated into the SINGLE Coraza config of a shared
// node, so a line Coraza cannot parse makes every later /load fail for every
// tenant on that node. Two gates follow from that: only a Sec* directive may
// be stored at all (no Include, which would pull a file into the rule set),
// and a scoped admin - who shares the node but answers for one tenant - may
// only suppress rules by id.

// ValidateWAFDirectives screens custom SecLang on the write path. unrestricted
// marks a platform admin with no client/reseller boundary.
func ValidateWAFDirectives(raw string, unrestricted bool) error {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := wafLineOK(line); err != nil {
			return err
		}
		if unrestricted {
			continue
		}
		if err := wafRemoveByIDOnly(line); err != nil {
			return err
		}
	}
	return nil
}

// SanitizeWAFDirectives drops stored lines that fail the structural screen and
// reports whether anything was removed. Emission-side companion of the
// validator: legacy rows must not be able to brick a node's config push.
func SanitizeWAFDirectives(raw string) (string, bool) {
	lines := strings.Split(raw, "\n")
	kept := make([]string, 0, len(lines))
	dropped := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") || wafLineOK(trimmed) == nil {
			kept = append(kept, trimmed)
			continue
		}
		dropped = true
	}
	return strings.Join(kept, "\n"), dropped
}

// wafLineOK is the structural screen every stored line must pass.
func wafLineOK(line string) error {
	if len(line) > 2048 {
		return fmt.Errorf("WAF directive line too long (2048 max)")
	}
	for _, r := range line {
		if r < 0x20 && r != '\t' {
			return fmt.Errorf("WAF directive contains a control character")
		}
	}
	if strings.Count(line, `"`)%2 != 0 {
		return fmt.Errorf("WAF directive has an unbalanced quote: %q", line)
	}
	name := line
	if i := strings.IndexAny(line, " \t"); i > 0 {
		name = line[:i]
	}
	if !strings.HasPrefix(name, "Sec") || len(name) < 4 {
		return fmt.Errorf("WAF directive %q is not a Sec* directive", name)
	}
	for _, r := range name[3:] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return fmt.Errorf("WAF directive %q is not a Sec* directive", name)
		}
	}
	return nil
}

// wafRemoveByIDOnly is the structured subset a scoped admin may write.
func wafRemoveByIDOnly(line string) error {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "SecRuleRemoveById" {
		return fmt.Errorf("only SecRuleRemoveById with numeric rule ids is allowed here (got %q)", fields[0])
	}
	for _, id := range fields[1:] {
		lo, hi, isRange := strings.Cut(id, "-")
		if !wafNumericID(lo) || (isRange && !wafNumericID(hi)) {
			return fmt.Errorf("SecRuleRemoveById takes numeric rule ids, got %q", id)
		}
	}
	return nil
}

func wafNumericID(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n <= 999999999
}
