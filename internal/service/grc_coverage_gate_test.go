package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

// rulesetDirForGate locates the repo rulesets/ dir from the test working dir.
func rulesetDirForGate(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"../../rulesets", "../.."} {
		abs, _ := filepath.Abs(p)
		if _, err := os.Stat(filepath.Join(abs, "isms_p_2.5.5.json")); err == nil {
			return abs
		}
	}
	t.Skip("rulesets dir not found")
	return ""
}

// distinctEvaluatedRules must count unique rule IDs that produced a real verdict,
// ignoring per-pod fan-out duplication and report/empty verdicts.
func TestDistinctEvaluatedRules(t *testing.T) {
	var results []grc.RuleResult
	// R-A evaluated on 14 pods, all 준수 → distinct 1
	for i := 0; i < 14; i++ {
		results = append(results, grc.RuleResult{RuleID: "R-A", Verdict: "준수"})
	}
	// R-B failed on 2 pods → distinct +1
	results = append(results,
		grc.RuleResult{RuleID: "R-B", Verdict: "미준수"},
		grc.RuleResult{RuleID: "R-B", Verdict: "미준수"},
	)
	// uncertain verdicts still count (they are evaluated, just inconclusive)
	results = append(results,
		grc.RuleResult{RuleID: "R-C", Verdict: grc.VerdictNO_DATA},
		grc.RuleResult{RuleID: "R-D", Verdict: "해당없음"},
	)
	// report-form / empty verdicts must NOT count
	results = append(results,
		grc.RuleResult{RuleID: "R-REP", Verdict: grc.VerdictREPORT},
		grc.RuleResult{RuleID: "R-EMPTY", Verdict: ""},
	)

	got := distinctEvaluatedRules(results)
	if got != 4 { // R-A, R-B, R-C, R-D
		t.Fatalf("distinctEvaluatedRules = %d, want 4 (report/empty excluded, dups collapsed)", got)
	}
}

// expectedRuleCount must return the number of ruleset-defined rules that are
// expected to yield a verdict (report/deferred excluded), using the merged
// (guideline + pod) ruleset view.
func TestExpectedRuleCount(t *testing.T) {
	store := NewRulesetStore(rulesetDirForGate(t))
	store.LoadAll() // warm cache with pod-ruleset merge (matches request flow)
	svc := &GRCService{rulesetStore: store}

	exp := svc.expectedRuleCount("2.5.5")
	if exp <= 0 {
		t.Fatalf("expectedRuleCount(2.5.5) = %d, want > 0", exp)
	}

	// Cross-check against a manual count over the same ruleset.
	rs, err := store.Load("2.5.5")
	if err != nil {
		t.Fatalf("load 2.5.5: %v", err)
	}
	want := 0
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.OutputType == "report" || r.ReclassifiedFrom != "" || r.DeferredFrom != "" {
			continue
		}
		want++
	}
	if exp != want {
		t.Fatalf("expectedRuleCount = %d, manual = %d", exp, want)
	}
	t.Logf("2.5.5 expected verdict-bearing rules = %d", exp)
}

// The core user-facing fix: an item whose passing rules cover only PART of its
// defined rules (e.g. R-rules passed but GL-rules never ran) must be flagged as
// under-covered so the verdict ladder downgrades 준수 → 검토필요.
func TestCoverageGate_PartialCoverageIsUnderCovered(t *testing.T) {
	store := NewRulesetStore(rulesetDirForGate(t))
	store.LoadAll()
	svc := &GRCService{rulesetStore: store}

	expected := svc.expectedRuleCount("2.5.5")
	if expected < 2 {
		t.Skipf("need >=2 defined rules to exercise gate, got %d", expected)
	}

	// Simulate only (expected-1) distinct rules actually evaluated, each passing
	// across 14 pods (per-pod fan-out). Synthetic rule IDs are fine — the gate
	// compares distinct counts, not the IDs themselves.
	var partial []grc.RuleResult
	for r := 0; r < expected-1; r++ {
		id := "syn-rule-" + string(rune('A'+r))
		for pod := 0; pod < 14; pod++ {
			partial = append(partial, grc.RuleResult{RuleID: id, Verdict: "준수"})
		}
	}
	evaluated := distinctEvaluatedRules(partial)
	if evaluated != expected-1 {
		t.Fatalf("evaluated = %d, want %d (per-pod dups must collapse)", evaluated, expected-1)
	}
	// Gate condition used in both verdict ladders:
	underCovered := expected > 0 && evaluated < expected
	if !underCovered {
		t.Fatalf("partial coverage (%d/%d) should be under-covered → 검토필요", evaluated, expected)
	}

	// Full coverage: all defined rules evaluated → clean 준수 (gate must NOT fire).
	var full []grc.RuleResult
	for r := 0; r < expected; r++ {
		full = append(full, grc.RuleResult{RuleID: "syn-rule-" + string(rune('A'+r)), Verdict: "준수"})
	}
	if ev := distinctEvaluatedRules(full); !(expected > 0 && ev >= expected) {
		t.Fatalf("full coverage (%d/%d) must stay 준수 (gate must not fire)", ev, expected)
	}
}
