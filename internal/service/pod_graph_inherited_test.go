package service

import (
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

// fanOutVerdict: 실제 결함·검토대상만 투영하고 N/A·준수·스킵·리포트는 제외한다 (DESIGN §9).
func TestFanOutVerdict(t *testing.T) {
	keep := []string{grc.VerdictNOT_MET, "미준수", grc.VerdictNEEDS_REVIEW, "검토필요",
		grc.VerdictNO_DATA, grc.VerdictINDETERMINATE}
	drop := []string{grc.VerdictNA, "해당없음", grc.VerdictMET, "준수",
		grc.VerdictSKIPPED, "skip", grc.VerdictREPORT}

	for _, v := range keep {
		if !fanOutVerdict(v) {
			t.Errorf("fanOutVerdict(%q) = false, want true (결함/검토대상은 투영)", v)
		}
	}
	for _, v := range drop {
		if fanOutVerdict(v) {
			t.Errorf("fanOutVerdict(%q) = true, want false (결함 아님 → fan-out 제외)", v)
		}
	}
}

// selectInheritedFindings: cluster/account 스코프 결함만 골라 inherited:true + owner_hint를 찍고,
// pod/pod_chain 스코프와 N/A·준수 결함은 제외한다.
func TestSelectInheritedFindings(t *testing.T) {
	items := []grc.ItemComplianceResult{{
		ISMSPItemID: "2.6.1",
		RuleResults: []grc.RuleResult{
			{RuleID: "R-2.6.1-03", Scope: grc.ScopeCluster, Verdict: grc.VerdictNOT_MET}, // keep
			{RuleID: "R-2.9.4-01", Scope: grc.ScopeAccount, Verdict: "미준수"},               // keep
			{RuleID: "R-2.7.1-01", Scope: grc.ScopeCluster, Verdict: grc.VerdictNA},       // drop: 해당없음
			{RuleID: "R-2.6.6-01", Scope: grc.ScopeAccount, Verdict: grc.VerdictMET},      // drop: 준수
			{RuleID: "R-2.6.1-01", Scope: grc.ScopePod, Verdict: grc.VerdictNOT_MET},      // drop: pod 스코프
			{RuleID: "R-2.5.5-01", Scope: grc.ScopePodChain, Verdict: grc.VerdictNOT_MET}, // drop: pod_chain
		},
	}}

	got := selectInheritedFindings(items)
	if len(got) != 2 {
		t.Fatalf("got %d inherited findings, want 2: %+v", len(got), got)
	}

	byRule := map[string]grc.RuleResult{}
	for _, rr := range got {
		byRule[rr.RuleID] = rr
		if !rr.Inherited {
			t.Errorf("%s: Inherited = false, want true", rr.RuleID)
		}
	}
	if h := byRule["R-2.6.1-03"].OwnerHint; h != grc.OwnerClusterAdmin {
		t.Errorf("cluster finding owner_hint = %q, want %q", h, grc.OwnerClusterAdmin)
	}
	if h := byRule["R-2.9.4-01"].OwnerHint; h != grc.OwnerAccountAdmin {
		t.Errorf("account finding owner_hint = %q, want %q", h, grc.OwnerAccountAdmin)
	}
}

// 같은 클러스터 결함(R-2.6.1-03)이 pod마다 평가돼 여러 item/결과로 들어와도
// canonical_id로 dedup되어 fan-out 표시 목록엔 1건만 남는다(점수 N배 폭발 방지의 표시 짝).
func TestSelectInheritedFindings_DedupsByCanonicalID(t *testing.T) {
	cid := grc.CanonicalID(grc.ScopeCluster, "prod", "", "", "", "R-2.6.1-03")
	mk := func() grc.RuleResult {
		return grc.RuleResult{RuleID: "R-2.6.1-03", Scope: grc.ScopeCluster,
			Verdict: grc.VerdictNOT_MET, CanonicalID: cid}
	}
	items := []grc.ItemComplianceResult{{
		ISMSPItemID: "2.6.1",
		RuleResults: []grc.RuleResult{mk(), mk(), mk()}, // pod A/B/C가 각각 평가한 동일 결함
	}}

	got := selectInheritedFindings(items)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (canonical_id로 dedup)", len(got))
	}
	if got[0].CanonicalID != cid {
		t.Fatalf("canonical_id = %q, want %q", got[0].CanonicalID, cid)
	}
}

// stampInheritedScope: cluster/account 룰에만 scope/canonical/inherited를 찍고,
// pod·pod_chain 룰은 건드리지 않아 pod별 distinct(빈 canonical)가 유지된다.
func TestStampInheritedScope(t *testing.T) {
	t.Run("cluster rule gets stamped", func(t *testing.T) {
		rr := grc.RuleResult{RuleID: "R-2.6.1-03"}
		stampInheritedScope(&rr, &Rule{RuleID: "R-2.6.1-03", RiskScope: grc.ScopeCluster}, "prod")
		if rr.Scope != grc.ScopeCluster || !rr.Inherited {
			t.Fatalf("scope/inherited not set: %+v", rr)
		}
		if rr.CanonicalID != "cluster:prod:R-2.6.1-03" {
			t.Fatalf("canonical_id = %q", rr.CanonicalID)
		}
		if rr.OwnerHint != grc.OwnerClusterAdmin {
			t.Fatalf("owner_hint = %q", rr.OwnerHint)
		}
	})
	t.Run("pod rule left untouched", func(t *testing.T) {
		rr := grc.RuleResult{RuleID: "R-2.6.1-01"}
		stampInheritedScope(&rr, &Rule{RuleID: "R-2.6.1-01", RiskScope: grc.ScopePod}, "prod")
		if rr.Scope != "" || rr.Inherited || rr.CanonicalID != "" {
			t.Fatalf("pod rule must stay unstamped (distinct per pod): %+v", rr)
		}
	})
}

// 기존에 owner_hint가 채워져 있으면 덮어쓰지 않는다.
func TestSelectInheritedFindings_PreservesOwnerHint(t *testing.T) {
	items := []grc.ItemComplianceResult{{
		RuleResults: []grc.RuleResult{
			{RuleID: "R-x", Scope: grc.ScopeCluster, Verdict: grc.VerdictNOT_MET, OwnerHint: "platform-sre"},
		},
	}}
	got := selectInheritedFindings(items)
	if len(got) != 1 || got[0].OwnerHint != "platform-sre" {
		t.Fatalf("owner_hint should be preserved, got %+v", got)
	}
}
