package engine

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// principalExtraNotes 는 권한 경계/신뢰 정책 등 보조 노트를 만든다.
// (Python principal_extra_notes 대응)
func principalExtraNotes(kind string, hasBoundary bool, assumeRoleDoc json.RawMessage) []string {
	notes := []string{}
	if hasBoundary {
		notes = append(notes, "권한 경계(permissions boundary) 적용됨 — 유효 권한은 더 제한적일 수 있음")
	}
	if kind == "role" && len(bytes.TrimSpace(assumeRoleDoc)) > 0 {
		trust := normalizeDoc(assumeRoleDoc)
		for _, s := range trust.Statement {
			if principalHasStar(s.Principal) {
				notes = append(notes, "신뢰 정책 Principal 이 '*' — 광범위하게 가정 가능(별도 점검 권장)")
				break
			}
		}
	}
	return notes
}

// assessPrincipal 은 한 principal 의 (출처,Statement) 목록을 룰셋으로 평가해 결과를 만든다.
// (Python assess_principal 대응)
func assessPrincipal(name, arn, kind string, statements []sourcedStatement, rs Ruleset, extraNotes []string) PrincipalResult {
	// 평가가 필요한 모든 액션(룰 + 콤보 구성요소).
	targets := map[string]bool{}
	for _, r := range rs.Rules {
		targets[r.Action] = true
	}
	for _, c := range rs.Combos {
		for _, a := range c.AllOf {
			targets[a] = true
		}
		for _, a := range c.AnyOf {
			targets[a] = true
		}
	}
	effective := make(map[string]evalResult, len(targets))
	for act := range targets {
		effective[act] = evaluateAction(statements, act)
	}

	findings := []Finding{}

	// 단일 액션 룰 (룰셋 순서대로).
	for _, r := range rs.Rules {
		ev := effective[r.Action]
		if !ev.allowed {
			continue
		}
		sev, notes := adjustSeverity(r.Severity, ev.details)
		findings = append(findings, Finding{
			Type:         "rule",
			ID:           r.ID,
			Action:       r.Action,
			Severity:     sev,
			BaseSeverity: r.Severity,
			Core:         r.Core,
			TitleKo:      r.TitleKo,
			Category:     r.Category,
			Notes:        notes,
			Sources:      sortedSources(ev.details),
			AwsDoc:       r.AwsDoc,
		})
	}

	// 콤보 룰 (룰셋 순서대로, 단일 룰 뒤에 append).
	for _, c := range rs.Combos {
		allOk := true
		for _, a := range c.AllOf {
			if !effective[a].allowed {
				allOk = false
				break
			}
		}
		anyOk := len(c.AnyOf) == 0
		if !anyOk {
			for _, a := range c.AnyOf {
				if effective[a].allowed {
					anyOk = true
					break
				}
			}
		}
		if !(allOk && anyOk) {
			continue
		}
		// 매칭된 구성요소(all_of 먼저, 그다음 any_of) 순서 보존.
		comps := make([]string, 0, len(c.AllOf)+len(c.AnyOf))
		for _, a := range c.AllOf {
			if effective[a].allowed {
				comps = append(comps, a)
			}
		}
		for _, a := range c.AnyOf {
			if effective[a].allowed {
				comps = append(comps, a)
			}
		}
		findings = append(findings, Finding{
			Type:         "combo",
			ID:           c.ID,
			Action:       strings.Join(comps, " + "),
			Severity:     c.Severity,
			BaseSeverity: c.Severity,
			Core:         true,
			TitleKo:      c.TitleKo,
			Category:     "콤보",
			Notes:        []string{c.DescKo},
			Sources:      []string{},
			AwsDoc:       "",
		})
	}

	// severity 내림차순 안정정렬(동일 severity 내 삽입 순서 유지 = 룰 먼저, 콤보 나중).
	sort.SliceStable(findings, func(i, j int) bool {
		return SeverityRank[findings[i].Severity] > SeverityRank[findings[j].Severity]
	})

	worst := "ok"
	for _, f := range findings {
		if SeverityRank[f.Severity] > SeverityRank[worst] {
			worst = f.Severity
		}
	}

	return PrincipalResult{
		Name:     name,
		Arn:      arn,
		Kind:     kind,
		Status:   worst,
		Findings: findings,
		Notes:    extraNotes,
	}
}

// sortedSources 는 allow 출처를 중복 제거 후 오름차순 정렬한다(비-nil 보장).
func sortedSources(details []allowDetail) []string {
	set := map[string]struct{}{}
	for _, d := range details {
		set[d.source] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
