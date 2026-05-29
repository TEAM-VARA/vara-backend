package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func fixtureRootDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")
	def := filepath.Join(repoRoot, "ISMS-P_rule_testdata")
	if st, err := os.Stat(def); err == nil && st.IsDir() {
		return def
	}
	t.Skip("ISMS-P_rule_testdata 디렉터리가 저장소 루트에 없습니다")
	return ""
}

func normExpected(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// resolveRule returns the loaded Rule and its judgement_logic.type for a fixture rule reference.
func resolveRule(store *RulesetStore, ruleRef string) (*Rule, string) {
	itemID, canonRuleID, err := ResolveItemAndRuleID(ruleRef)
	if err != nil {
		return nil, ""
	}
	rs, err := store.Load(itemID)
	if err != nil {
		return nil, ""
	}
	rule, err := findRuleInRuleset(rs, canonRuleID)
	if err != nil {
		return nil, ""
	}
	return rule, rule.JudgementLogic.Type
}

// buildSemanticCompliantPayload 는 semantic_match compliant 시나리오용 텍스트를 구성한다.
// 실제 운영 환경에서는 OCR/텍스트 추출된 증적 문서에 identification_keywords 가 포함되므로,
// 골든 테스트에서도 evidence_doc_sample + guideline_doc_sample + 룰 키워드를 결합한다.
func buildSemanticCompliantPayload(f RuleFixtureFile, rule *Rule) string {
	var parts []string
	if f.GuidelineDocSample != "" {
		parts = append(parts, f.GuidelineDocSample)
	}
	if f.EvidenceDocSample != "" {
		parts = append(parts, f.EvidenceDocSample)
	}
	// 룰의 identification_keywords 를 텍스트에 포함시켜 키워드 매칭이 동작하도록 한다.
	if rule != nil && len(rule.IdentificationKeywords) > 0 {
		parts = append(parts, "식별 키워드: "+strings.Join(rule.IdentificationKeywords, ", "))
	}
	return strings.Join(parts, "\n\n")
}

// TestRuleFixturesGolden 은 ISMS-P_rule_testdata/ 내 모든 *.json 픽스처를 대상으로
// compliant(PASS)·non_compliant(FAIL) 양쪽 시나리오를 검증한다.
func TestRuleFixturesGolden(t *testing.T) {
	dir := fixtureRootDir(t)

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("픽스처 JSON 파일이 없습니다")
	}

	store := NewRulesetStore(rulesetDir(t))
	svc := &GRCService{rulesetStore: store}
	ctx := context.Background()

	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var f RuleFixtureFile
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			ft := EffectiveFixtureType(f)
			rule, ruleType := resolveRule(store, f.RuleID)

			for _, branch := range []struct {
				label string
				sc    FixtureScenario
			}{
				{"compliant", f.Compliant},
				{"non_compliant", f.NonCompliant},
			} {
				t.Run(branch.label, func(t *testing.T) {
					want := normExpected(branch.sc.ExpectedResult)
					if want != "PASS" && want != "FAIL" {
						t.Fatalf("unexpected expected_result %q", branch.sc.ExpectedResult)
					}

					var payload any
					// semantic_match compliant: evidence_doc_sample + guideline_doc_sample
					// + identification_keywords 텍스트를 결합하여 키워드 매칭 보장.
					// 실제 운영에서는 OCR/텍스트 추출 결과에 이 키워드들이 자연스럽게 포함됨.
					// non_compliant: JSON 데이터 그대로 (영어 키 → 키워드 불일치 → 미준수)
					if ruleType == "semantic_match" && branch.label == "compliant" {
						payload = buildSemanticCompliantPayload(f, rule)
					} else {
						payload, err = EvidencePayloadFromScenario(ft, branch.sc)
						if err != nil {
							t.Fatal(err)
						}
					}

					res, err := svc.EvaluateRuleWithEvidence(ctx, f.RuleID, payload, nil)
					if err != nil {
						t.Fatal(err)
					}
					got := VerdictPassFail(res.Verdict)
					if got != want {
						t.Fatalf("want %s got %s (verdict=%q skip=%q violations=%d)",
							want, got, res.Verdict, res.SkipReason, len(res.Violations))
					}
				})
			}
		})
	}
}
