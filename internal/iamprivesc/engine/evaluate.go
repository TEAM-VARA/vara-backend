package engine

// allowDetail 은 한 Allow Statement 가 액션을 허용한 근거(출처/리소스 범위/조건).
type allowDetail struct {
	source       string
	hasStar      bool
	hasCondition bool
}

// sourcedStatement 는 (출처 라벨, Statement) 쌍.
type sourcedStatement struct {
	source string
	stmt   Statement
}

// evalResult 는 한 액션에 대한 평가 결과.
type evalResult struct {
	allowed bool
	details []allowDetail
	denied  bool
}

// evaluateAction 은 주어진 statements 에서 target 액션의 (allowed, allowDetails, denied)를 구한다.
// denied: 무조건(*, 조건없음) Deny 가 액션을 차단하면 true. (Python evaluate_action 대응)
func evaluateAction(statements []sourcedStatement, target string) evalResult {
	var details []allowDetail
	denied := false
	for _, ps := range statements {
		if !ps.stmt.coversAction(target) {
			continue
		}
		hasCond := len(ps.stmt.Condition) > 0
		star := ps.stmt.resolveStar()
		switch ps.stmt.Effect {
		case "Allow":
			details = append(details, allowDetail{source: ps.source, hasStar: star, hasCondition: hasCond})
		case "Deny":
			if star && !hasCond {
				denied = true
			}
		}
	}
	return evalResult{allowed: len(details) > 0 && !denied, details: details, denied: denied}
}

// adjustSeverity 는 리소스 범위·조건에 따라 위험도를 보정하고 사람이 읽을 노트를 만든다.
// (Python adjust_severity 대응)
func adjustSeverity(base string, details []allowDetail) (string, []string) {
	notes := []string{}
	sev := base

	anyStar := false
	for _, d := range details {
		if d.hasStar {
			anyStar = true
			break
		}
	}
	allCond := len(details) > 0
	for _, d := range details {
		if !d.hasCondition {
			allCond = false
			break
		}
	}

	if !anyStar && len(details) > 0 {
		notes = append(notes, "리소스 범위가 특정 ARN 으로 제한됨")
		sev = downgrade(sev)
	} else {
		notes = append(notes, "Resource:* (전체 리소스 대상)")
	}
	if allCond {
		notes = append(notes, "Condition 존재 — 실제 적용 여부 추가 검토 필요")
		sev = downgrade(sev)
	}
	return sev, notes
}
