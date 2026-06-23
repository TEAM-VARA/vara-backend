package engine

import "sort"

// DetectSnapshot 은 한 계정 스냅샷을 룰셋으로 평가해 정렬된 결과와 요약을 반환한다.
// (Python detect_snapshot 대응) 결과는 (위험도 내림차순, kind, name) 으로 정렬된다.
func DetectSnapshot(snap Snapshot, rs Ruleset) ([]PrincipalResult, Summary) {
	managedIndex := buildManagedPolicyIndex(snap.Policies)
	groupsByName := make(map[string]GroupDetail, len(snap.Groups))
	for _, g := range snap.Groups {
		groupsByName[g.GroupName] = g
	}

	results := []PrincipalResult{}
	for _, u := range snap.Users {
		stmts := collectPrincipalStatements("user", u.UserPolicyList, u.AttachedManagedPolicies,
			u.GroupList, managedIndex, groupsByName)
		notes := principalExtraNotes("user", u.PermissionsBoundary != nil, nil)
		results = append(results, assessPrincipal(u.UserName, u.Arn, "user", stmts, rs, notes))
	}
	for _, r := range snap.Roles {
		stmts := collectPrincipalStatements("role", r.RolePolicyList, r.AttachedManagedPolicies,
			nil, managedIndex, groupsByName)
		notes := principalExtraNotes("role", r.PermissionsBoundary != nil, r.AssumeRolePolicyDocument)
		results = append(results, assessPrincipal(r.RoleName, r.Arn, "role", stmts, rs, notes))
	}
	for _, g := range snap.Groups {
		stmts := collectPrincipalStatements("group", g.GroupPolicyList, g.AttachedManagedPolicies,
			nil, managedIndex, groupsByName)
		notes := principalExtraNotes("group", false, nil)
		results = append(results, assessPrincipal(g.GroupName, g.Arn, "group", stmts, rs, notes))
	}

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if SeverityRank[a.Status] != SeverityRank[b.Status] {
			return SeverityRank[a.Status] > SeverityRank[b.Status]
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})

	sum := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case "critical":
			sum.Critical++
		case "warning":
			sum.Warning++
		case "info":
			sum.Info++
		case "ok":
			sum.Ok++
		}
	}
	return results, sum
}
