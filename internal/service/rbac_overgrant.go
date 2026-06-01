package service

import (
	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ────────────────────────────────────────────────────
// RBAC 과다 부여 분석
//
// 기존 rbac_score는 권한의 "위험도"를 본다 (cluster-admin 70점 등).
// 과다 부여 분석은 "넓이"를 본다 (얼마나 많은 verb/resource에 권한이 있는지).
//
// 두 가지 다른 차원의 분석:
//   - rbac_score:   "위험한 권한이 있나" (수직)
//   - overgrant:    "권한이 너무 넓은가" (수평)
//
// 둘 다 봐야 진짜 위험 평가 가능.
// ────────────────────────────────────────────────────

// AnalyzeOvergrant — Pod의 RBAC rules에서 과다부여 정도 분석
//
// 입력:
//   rules: Pod의 ServiceAccount에 바인딩된 모든 rules (cluster_*_roles에서)
//   bindingCount: 매칭된 Binding 개수
//
// 출력:
//   OvergrantPermissions, overgrant_ratio
//
// overgrant_ratio 계산:
//   - wildcard verbs ("*") → 1.0 (최대 과다)
//   - 6 verbs 이상 → 0.7+
//   - secret/configmap/node 접근 → +0.2
//   - 1~2 verbs (정상 최소 권한) → 0.0~0.2
func AnalyzeOvergrant(
	rules []postgres.RoleRule,
	bindingCount int,
) (*scoring.OvergrantPermissions, float64) {
	if len(rules) == 0 {
		return nil, 0.0
	}

	verbs := make(map[string]struct{})
	resources := make(map[string]struct{})
	hasWildcardVerbs := false
	hasWildcardResources := false
	hasSecretAccess := false
	hasConfigMapAccess := false
	hasNodeAccess := false
	hasPodExec := false

	for _, rule := range rules {
		for _, v := range rule.Verbs {
			verbs[v] = struct{}{}
			if v == "*" {
				hasWildcardVerbs = true
			}
		}
		for _, r := range rule.Resources {
			resources[r] = struct{}{}
			switch r {
			case "*":
				hasWildcardResources = true
			case "secrets":
				hasSecretAccess = true
			case "configmaps":
				hasConfigMapAccess = true
			case "nodes":
				hasNodeAccess = true
			case "pods/exec":
				hasPodExec = true
			}
		}
		// pods/exec 은 보통 resources=["pods/exec"]지만
		// 일부는 resources=["pods"] + verbs=["exec"] 패턴
		for _, v := range rule.Verbs {
			if v == "exec" {
				for _, r := range rule.Resources {
					if r == "pods" {
						hasPodExec = true
					}
				}
			}
		}
	}

	verbsList := make([]string, 0, len(verbs))
	for v := range verbs {
		verbsList = append(verbsList, v)
	}

	highPrivResources := []string{}
	if hasSecretAccess {
		highPrivResources = append(highPrivResources, "secrets")
	}
	if hasConfigMapAccess {
		highPrivResources = append(highPrivResources, "configmaps")
	}
	if hasNodeAccess {
		highPrivResources = append(highPrivResources, "nodes")
	}
	if hasPodExec {
		highPrivResources = append(highPrivResources, "pods/exec")
	}

	// overgrant_ratio 계산
	var ratio float64

	switch {
	case hasWildcardVerbs && hasWildcardResources:
		ratio = 1.0 // cluster-admin 수준
	case hasWildcardVerbs || hasWildcardResources:
		ratio = 0.85
	case len(verbs) >= 6:
		ratio = 0.7
	case len(verbs) >= 4:
		ratio = 0.5
	case len(verbs) >= 2:
		ratio = 0.3
	default:
		ratio = 0.1
	}

	// 민감 리소스 접근 → +0.1씩
	if hasSecretAccess {
		ratio += 0.1
	}
	if hasNodeAccess {
		ratio += 0.1
	}
	if hasPodExec {
		ratio += 0.1
	}

	// clamp to [0, 1]
	if ratio > 1.0 {
		ratio = 1.0
	}

	overgrant := &scoring.OvergrantPermissions{
		DefinedVerbs: verbsList,
		RBACSummary: scoring.RBACSummary{
			HasWildcardVerbs:     hasWildcardVerbs,
			HasWildcardResources: hasWildcardResources,
			HasSecretAccess:      hasSecretAccess,
			HasConfigMapAccess:   hasConfigMapAccess,
			HasNodeAccess:        hasNodeAccess,
			HasPodExec:           hasPodExec,
			VerbCount:            len(verbs),
			ResourceCount:        len(resources),
		},
		BindingCount:           bindingCount,
		HighPrivilegeResources: highPrivResources,
		OvergrantRatio:         ratio,
	}

	return overgrant, ratio
}
