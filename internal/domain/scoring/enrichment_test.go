package scoring

import "testing"

func TestParseCVSSFlags(t *testing.T) {
	tests := []struct {
		name                                                 string
		vec                                                  string
		remote, avail, conf, scopeChanged, unauth            bool
	}{
		{
			name: "v3.1 RCE AV:N PR:N S:U C:H/I:H/A:H",
			vec:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			remote: true, avail: true, conf: true, scopeChanged: false, unauth: true,
		},
		{
			name: "v3.1 scope changed, local, auth required",
			vec:  "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N",
			remote: false, avail: false, conf: true, scopeChanged: true, unauth: false,
		},
		{
			// "AC:H"가 "C:H"로 오인되면 안 된다(키:값 정확 매칭).
			name: "AC:H must not be read as C:H",
			vec:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
			remote: true, avail: false, conf: false, scopeChanged: false, unauth: true,
		},
		{
			name: "v4.0 subsequent system impact = scopeChanged",
			vec:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N",
			remote: true, avail: true, conf: true, scopeChanged: true, unauth: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, a, c, s, u := ParseCVSSFlags(tc.vec)
			if r != tc.remote || a != tc.avail || c != tc.conf || s != tc.scopeChanged || u != tc.unauth {
				t.Errorf("ParseCVSSFlags(%q) = (r%v a%v c%v s%v u%v), want (r%v a%v c%v s%v u%v)",
					tc.vec, r, a, c, s, u, tc.remote, tc.avail, tc.conf, tc.scopeChanged, tc.unauth)
			}
		})
	}
}

func TestDeriveImpact(t *testing.T) {
	if got := DeriveImpact([]string{"CWE-502"}, false, false); got != "RCE" {
		t.Errorf("deserialization CWE → want RCE, got %q", got)
	}
	if got := DeriveImpact([]string{"CWE-400"}, false, false); got != "DoS" {
		t.Errorf("resource-exhaustion CWE → want DoS, got %q", got)
	}
	if got := DeriveImpact(nil, true, false); got != "DoS" {
		t.Errorf("availability flag → want DoS, got %q", got)
	}
	if got := DeriveImpact(nil, false, true); got != "Info Disclosure" {
		t.Errorf("confidentiality flag → want Info Disclosure, got %q", got)
	}
	if got := DeriveImpact(nil, false, false); got != "" {
		t.Errorf("no signal → want empty, got %q", got)
	}
}

func TestDeriveAttack(t *testing.T) {
	// RCE ∧ remote ∧ unauth → T1190, _validated:false
	a := DeriveAttack("RCE", true, true)
	if a == nil || len(a.TechniqueIDs) != 1 || a.TechniqueIDs[0] != "T1190" {
		t.Fatalf("RCE/remote/unauth → want [T1190], got %+v", a)
	}
	if a.Validated {
		t.Error("attack mapping must be _validated:false (정책)")
	}
	// remote but not unauth RCE → T1210
	if a := DeriveAttack("Info Disclosure", true, false); a == nil || a.TechniqueIDs[0] != "T1210" {
		t.Errorf("remote non-unauth → want [T1210], got %+v", a)
	}
	// not remote → nil
	if a := DeriveAttack("RCE", false, true); a != nil {
		t.Errorf("local → want nil attack, got %+v", a)
	}
}

func TestDeriveMitigations(t *testing.T) {
	pre := []Precondition{
		{ID: "default_servlet_write", Negation: "Default Servlet write 비활성화(readonly=true)"},
		{ID: "no_negation"}, // negation 없으면 CONFIG 항목 생략
	}
	ms := DeriveMitigations([]string{"9.0.99", "10.1.35"}, pre)

	var vuln, config, net int
	for _, m := range ms {
		switch m.Card {
		case "VULN":
			vuln++
			if m.AttackMitigation != "M1051" || m.GatedOnConfig {
				t.Errorf("VULN mitigation must be M1051 ungated, got %+v", m)
			}
		case "CONFIG":
			config++
			if m.AttackMitigation != "M1042" || !m.GatedOnConfig || m.Gate == "" {
				t.Errorf("CONFIG mitigation must be M1042 gated with gate id, got %+v", m)
			}
		case "NET":
			net++
			if m.AttackMitigation != "M1030" {
				t.Errorf("NET mitigation must be M1030, got %+v", m)
			}
		}
	}
	if vuln != 1 || config != 1 || net != 1 {
		t.Errorf("want 1 VULN / 1 CONFIG (negation 있는 것만) / 1 NET, got %d/%d/%d", vuln, config, net)
	}
}

func TestDeriveMitigations_NoFixedVersions(t *testing.T) {
	// fixed_versions 없으면 VULN(M1051) 항목 생략 (설계서 §8.3)
	ms := DeriveMitigations(nil, nil)
	for _, m := range ms {
		if m.Card == "VULN" {
			t.Errorf("no fixed_versions → VULN 카드 없어야 함, got %+v", m)
		}
	}
}

func TestBuildRenderedCard(t *testing.T) {
	score := func(s float64) *CVSSInfo {
		return &CVSSInfo{Resolved: CVSSResolved{DisplayScore: s}}
	}
	tests := []struct {
		name string
		e    *CVEEnrichment
		want string
	}{
		{
			name: "DoS — class==impact → 한 번만, KEV+PoC 배지 (OpenAPI example)",
			e: &CVEEnrichment{
				CVEID: "CVE-2023-44487", ModuleShort: "HTTP/2",
				VulnClassLabelShort: "DoS", Impact: "DoS",
				CVSS: score(7.5), Signals: &EnrichSignals{KEV: true, PublicPoC: true},
			},
			want: "HTTP/2 · DoS · CVE-2023-44487 CVSS 7.5 · KEV · PoC",
		},
		{
			name: "RCE — class≠impact → 결합, KEV+PoC (OpenAPI example)",
			e: &CVEEnrichment{
				CVEID: "CVE-2025-24813", ModuleShort: "Tomcat Default Servlet",
				VulnClassLabelShort: "역직렬화", Impact: "RCE",
				CVSS: score(9.8), Signals: &EnrichSignals{KEV: true, PublicPoC: true},
			},
			want: "Tomcat Default Servlet · 역직렬화 RCE · CVE-2025-24813 CVSS 9.8 · KEV · PoC",
		},
		{
			name: "module 미추출 → '취약 컴포넌트' 폴백, 배지 없음",
			e: &CVEEnrichment{
				CVEID: "CVE-2025-24813", Impact: "RCE",
				CVSS: score(9.8), Signals: &EnrichSignals{},
			},
			want: "취약 컴포넌트 · RCE · CVE-2025-24813 CVSS 9.8",
		},
		{
			name: "CVSS 결측 → 점수 토막 생략 (환각 점수 금지)",
			e: &CVEEnrichment{
				CVEID: "CVE-9999-00001", ModuleShort: "foo", Impact: "DoS",
			},
			want: "foo · DoS · CVE-9999-00001",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildRenderedCard(tt.e)
			if got == nil || got.Card != tt.want {
				t.Errorf("card mismatch\n got: %q\nwant: %q", cardOf(got), tt.want)
			}
		})
	}
	if BuildRenderedCard(nil) != nil {
		t.Error("nil enrichment → nil rendered")
	}
}

func cardOf(r *RenderedText) string {
	if r == nil {
		return "<nil>"
	}
	return r.Card
}
