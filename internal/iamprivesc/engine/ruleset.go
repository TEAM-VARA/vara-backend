package engine

import (
	_ "embed"
	"encoding/json"
	"os"
)

// 기본 룰셋은 통합본 전용 top9(iam_privesc_rules_top9.json) 이다.
// 더 넓은 커버리지의 확장 룰셋이 필요하면 --rules 로 경로를 지정한다.
//go:embed iam_privesc_rules_top9.json
var embeddedRules []byte

type Rule struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
	Core     bool   `json:"core"`
	Category string `json:"category"`
	TitleKo  string `json:"title_ko"`
	DescKo   string `json:"desc_ko"`
	AwsDoc   string `json:"aws_doc"`
}

type Combo struct {
	ID       string   `json:"id"`
	TitleKo  string   `json:"title_ko"`
	Severity string   `json:"severity"`
	AllOf    []string `json:"all_of"`
	AnyOf    []string `json:"any_of"`
	DescKo   string   `json:"desc_ko"`
}

type Ruleset struct {
	Name    string  `json:"ruleset"`
	Version string  `json:"version"`
	Rules   []Rule  `json:"rules"`
	Combos  []Combo `json:"combos"`
}

// LoadRuleset 는 path 가 비면 임베드된 룰셋을, 아니면 파일에서 읽어 파싱한다.
func LoadRuleset(path string) (Ruleset, error) {
	data := embeddedRules
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Ruleset{}, err
		}
		data = b
	}
	var rs Ruleset
	if err := json.Unmarshal(data, &rs); err != nil {
		return Ruleset{}, err
	}
	return rs, nil
}

// ApplyCoreOnly 는 core=true 룰만 남기고, all_of 가 모두 core 액션인 콤보만 유지한다.
// (Python apply_core_only / --core-only 대응)
func ApplyCoreOnly(rs Ruleset) Ruleset {
	coreActions := map[string]bool{}
	rules := make([]Rule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		if r.Core {
			rules = append(rules, r)
			coreActions[r.Action] = true
		}
	}
	combos := make([]Combo, 0, len(rs.Combos))
	for _, c := range rs.Combos {
		ok := true
		for _, a := range c.AllOf {
			if !coreActions[a] {
				ok = false
				break
			}
		}
		if ok {
			combos = append(combos, c)
		}
	}
	rs.Rules = rules
	rs.Combos = combos
	return rs
}
