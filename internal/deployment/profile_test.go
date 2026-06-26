package deployment

import "testing"

func TestParseFallsBackToProvider(t *testing.T) {
	// Empty and unknown both map to Default (provider) so legacy installs keep
	// the full menu.
	for _, in := range []string{"", "nonsense", "Homelab "} {
		if got := Parse(in); got != Default {
			t.Errorf("Parse(%q) = %q, want %q", in, got, Default)
		}
	}
	for _, p := range All() {
		if got := Parse(string(p)); got != p {
			t.Errorf("Parse(%q) = %q, want roundtrip", p, got)
		}
	}
}

func TestFeaturesAreCumulative(t *testing.T) {
	home := ProfileHomelab.Features()
	team := ProfileSmallTeam.Features()
	adv := ProfileAdvanced.Features()
	prov := ProfileProvider.Features()

	// homelab: minimal set only.
	if !home.Hosts || !home.Tunnels || !home.Map || !home.Backups || !home.Settings {
		t.Error("homelab missing a baseline module")
	}
	if home.Users || home.Nodes || home.Clients || home.Stats || home.WAF {
		t.Error("homelab leaked an advanced/team/provider module")
	}

	// smallteam adds users+audit, still no fleet/provider.
	if !team.Users || !team.Audit {
		t.Error("smallteam missing users/audit")
	}
	if team.Nodes || team.Clients || team.Stats {
		t.Error("smallteam leaked an advanced/provider module")
	}

	// advanced adds fleet/observability/security, still no customer model.
	if !adv.Nodes || !adv.Stats || !adv.WAF || !adv.APITokens || !adv.RestoreDrill {
		t.Error("advanced missing an advanced module")
	}
	if adv.Clients || adv.Plans || adv.Scopes {
		t.Error("advanced leaked a provider-only module")
	}

	// provider: everything on.
	if !prov.Clients || !prov.Plans || !prov.Services || !prov.Scopes || !prov.CustomerPortal {
		t.Error("provider missing a customer module")
	}
	if !prov.Nodes || !prov.Users || !prov.Hosts {
		t.Error("provider should be a superset of every lower tier")
	}
}

func TestProviderRequiresMySQL(t *testing.T) {
	if !ProfileProvider.DB().RequireMySQL {
		t.Error("provider must require MySQL")
	}
	if ProfileProvider.AllowsDriver("sqlite") {
		t.Error("provider must not allow sqlite")
	}
	if !ProfileProvider.AllowsDriver("mysql") {
		t.Error("provider must allow mysql")
	}
}

func TestSQLiteGatedByAvailability(t *testing.T) {
	// SQLite is policy-allowed for homelab but not yet wired, so the driver is
	// still rejected until SQLiteAvailable flips.
	if !ProfileHomelab.DB().SQLiteOK {
		t.Error("homelab policy should allow sqlite")
	}
	if ProfileHomelab.AllowsDriver("sqlite") != SQLiteAvailable {
		t.Errorf("homelab sqlite allowed = %v, want SQLiteAvailable=%v",
			ProfileHomelab.AllowsDriver("sqlite"), SQLiteAvailable)
	}
	if ProfileHomelab.AllowsDriver("postgres") {
		t.Error("unknown driver must be rejected")
	}
}

func TestDowngradeDetection(t *testing.T) {
	if ProfileHomelab.IsDowngrade(ProfileProvider) {
		t.Error("homelab -> provider is an upgrade, not a downgrade")
	}
	if !ProfileProvider.IsDowngrade(ProfileHomelab) {
		t.Error("provider -> homelab is a downgrade")
	}
	if ProfileAdvanced.IsDowngrade(ProfileAdvanced) {
		t.Error("same profile is not a downgrade")
	}
}

func TestModeStrings(t *testing.T) {
	if ProfileHomelab.UIMode() != "simple" || ProfileProvider.UIMode() != "provider" {
		t.Error("unexpected UIMode")
	}
	if ProfileProvider.TenantMode() != "multi" || ProfileAdvanced.TenantMode() != "single" {
		t.Error("unexpected TenantMode")
	}
}
