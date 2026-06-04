package service

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RuleFixtureFile mirrors ISMS-P rule test JSON (v2 schema, simplified).
type RuleFixtureFile struct {
	RuleID             string          `json:"rule_id"`
	FixtureType        string          `json:"fixture_type"`
	DataSource         string          `json:"data_source,omitempty"`
	Compliant          FixtureScenario `json:"compliant"`
	NonCompliant       FixtureScenario `json:"non_compliant"`
	EvidenceDocSample  string          `json:"evidence_doc_sample,omitempty"`
	GuidelineDocSample string          `json:"guideline_doc_sample,omitempty"`
}

// FixtureScenario is either k8s_data ("data") or document ("guideline" + "evidence").
type FixtureScenario struct {
	Description    string          `json:"description"`
	Data           json.RawMessage `json:"data,omitempty"`
	Guideline      string          `json:"guideline,omitempty"`
	Evidence       string          `json:"evidence,omitempty"`
	ExpectedResult string          `json:"expected_result"`
}

// EffectiveFixtureType infers k8s_data when fixture_type is omitted but "data" is present.
func EffectiveFixtureType(f RuleFixtureFile) string {
	if f.FixtureType != "" {
		return f.FixtureType
	}
	if len(f.Compliant.Data) > 0 || len(f.NonCompliant.Data) > 0 {
		return "k8s_data"
	}
	return "document"
}

// EvidencePayloadFromScenario converts one branch of a fixture file to a value suitable for
// EvaluateRuleWithEvidence (after CanonicalEvidenceForRule inside that method).
func EvidencePayloadFromScenario(fixtureType string, sc FixtureScenario) (any, error) {
	switch fixtureType {
	case "k8s_data":
		if len(sc.Data) == 0 {
			return nil, fmt.Errorf("k8s_data scenario has empty data")
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Data, &m); err != nil {
			return nil, fmt.Errorf("decode k8s data: %w", err)
		}
		return m, nil
	case "document":
		g := strings.TrimSpace(sc.Guideline)
		e := strings.TrimSpace(sc.Evidence)
		if g == "" && e == "" {
			return nil, fmt.Errorf("document scenario has empty guideline and evidence")
		}
		return g + "\n\n" + e, nil
	case "":
		// tolerate missing fixture_type when branch still has document fields
		if sc.Guideline != "" || sc.Evidence != "" {
			return strings.TrimSpace(sc.Guideline) + "\n\n" + strings.TrimSpace(sc.Evidence), nil
		}
		if len(sc.Data) > 0 {
			var m map[string]any
			if err := json.Unmarshal(sc.Data, &m); err != nil {
				return nil, err
			}
			return m, nil
		}
		return nil, fmt.Errorf("empty fixture_type and no document/k8s fields")
	default:
		if sc.Guideline != "" || sc.Evidence != "" {
			return strings.TrimSpace(sc.Guideline) + "\n\n" + strings.TrimSpace(sc.Evidence), nil
		}
		if len(sc.Data) > 0 {
			var m map[string]any
			if err := json.Unmarshal(sc.Data, &m); err != nil {
				return nil, err
			}
			return m, nil
		}
		return nil, fmt.Errorf("unknown fixture_type %q and no document/k8s fields", fixtureType)
	}
}
