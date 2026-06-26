package engine

import "fmt"

// buildManagedPolicyIndex 는 관리형 정책 ARN → 기본 버전 문서를 만든다.
// (Python build_managed_policy_index 대응)
func buildManagedPolicyIndex(policies []ManagedPolicy) map[string]PolicyDocument {
	index := map[string]PolicyDocument{}
	for _, p := range policies {
		var chosen *PolicyVersion
		for i := range p.PolicyVersionList {
			v := &p.PolicyVersionList[i]
			if v.IsDefaultVersion || v.VersionId == p.DefaultVersionId {
				chosen = v
				break
			}
		}
		if chosen == nil && len(p.PolicyVersionList) > 0 {
			chosen = &p.PolicyVersionList[0]
		}
		if chosen != nil {
			index[p.Arn] = normalizeDoc(chosen.Document)
		}
	}
	return index
}

func statementsFromDoc(doc PolicyDocument, source string) []sourcedStatement {
	out := make([]sourcedStatement, 0, len(doc.Statement))
	for _, s := range doc.Statement {
		out = append(out, sourcedStatement{source: source, stmt: s})
	}
	return out
}

// collectPrincipalStatements 는 principal 의 유효 (출처, Statement) 목록을 모은다.
// 사용자는 소속 그룹의 인라인/관리형 권한도 상속한다. 미해결 관리형은 드롭(Python 동일).
// (Python collect_principal_statements 대응)
func collectPrincipalStatements(
	kind string,
	inline []InlinePolicy,
	attached []AttachedPolicy,
	groupList []string,
	managedIndex map[string]PolicyDocument,
	groupsByName map[string]GroupDetail,
) []sourcedStatement {

	stmts := []sourcedStatement{}
	for _, pol := range inline {
		stmts = append(stmts, statementsFromDoc(normalizeDoc(pol.PolicyDocument), "인라인:"+pol.PolicyName)...)
	}
	for _, ap := range attached {
		if doc, ok := managedIndex[ap.PolicyArn]; ok {
			stmts = append(stmts, statementsFromDoc(doc, "관리형:"+ap.PolicyName)...)
		}
	}
	if kind == "user" {
		for _, gname := range groupList {
			grp, ok := groupsByName[gname]
			if !ok {
				continue
			}
			for _, pol := range grp.GroupPolicyList {
				stmts = append(stmts, statementsFromDoc(
					normalizeDoc(pol.PolicyDocument),
					fmt.Sprintf("그룹[%s] 인라인:%s", gname, pol.PolicyName))...)
			}
			for _, ap := range grp.AttachedManagedPolicies {
				if doc, ok := managedIndex[ap.PolicyArn]; ok {
					stmts = append(stmts, statementsFromDoc(doc,
						fmt.Sprintf("그룹[%s] 관리형:%s", gname, ap.PolicyName))...)
				}
			}
		}
	}
	return stmts
}
