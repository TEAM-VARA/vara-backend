package engine

import (
	"sort"
	"strings"
)

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
		// AWS 서비스 연결 역할(service-linked role)은 AWS 가 생성·관리하며 사용자가
		// 정책을 수정할 수 없다(ARN 경로 /aws-service-role/). 실제 권한상승 벡터가
		// 되기 어렵고 PassRole+RunInstances 같은 콤보에서 대량 오탐을 유발하므로,
		// 평가 대상에서 제외하고 기록만 남긴다(status=ok + 노트, findings 없음).
		if isServiceLinkedRole(r.Arn) {
			results = append(results, PrincipalResult{
				Name:     r.RoleName,
				Arn:      r.Arn,
				Kind:     "role",
				Status:   "ok",
				Findings: []Finding{},
				Notes:    []string{"AWS 서비스 연결 역할(/aws-service-role/) — 사용자 수정 불가, 권한상승 평가 제외"},
			})
			continue
		}
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

// isServiceLinkedRole 는 ARN 경로로 AWS 서비스 연결 역할(service-linked role)을 판별한다.
// SLR 은 항상 `/aws-service-role/` 경로에 생성되며(파티션 무관: aws/aws-cn/aws-us-gov),
// 역할 이름 접두사(AWSServiceRoleFor…)보다 ARN 경로가 신뢰할 수 있는 신호다.
func isServiceLinkedRole(arn string) bool {
	return strings.Contains(arn, ":role/aws-service-role/")
}
