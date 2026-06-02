package service

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/repository/postgres"
)

// toRawJSON marshals a []string slice to json.RawMessage.
// Returns nil if the slice is empty.
func toRawJSON(ss []string) json.RawMessage {
	if len(ss) == 0 {
		return nil
	}
	b, _ := json.Marshal(ss)
	return b
}

// ClusterSnapshot holds all cluster data needed for finding evaluation.
type ClusterSnapshot struct {
	ClusterName string
	SnapshotAt  time.Time

	Pods        []postgres.ClusterPodRow
	Namespaces  []string
	Related     *postgres.ClusterRelatedRows
}

// FindingEvalRequest is the API input for cluster-wide finding evaluation.
type FindingEvalRequest struct {
	CompanyID   string `json:"company_id"`
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace,omitempty"` // optional filter
}

// EvaluateManualRules evaluates all manual-judgment rules against a cluster snapshot.
func EvaluateManualRules(rules []Rule, snap *ClusterSnapshot) []grc.RuleResult {
	var results []grc.RuleResult
	for _, r := range rules {
		rr := evaluateSingleManualRule(r, snap)
		results = append(results, rr)
	}
	return results
}

func evaluateSingleManualRule(rule Rule, snap *ClusterSnapshot) grc.RuleResult {
	var meta *ManualRuleMeta
	if rule.ManualMeta != nil {
		meta = rule.ManualMeta
	} else {
		meta = &ManualRuleMeta{}
	}

	base := grc.RuleResult{
		RuleID:       rule.RuleID,
		JudgmentMode: "manual",
		VerdictType:  rule.VerdictType,
	}

	// Copy manual meta fields
	base.ComplianceMappings    = meta.ComplianceMappings
	base.KisaDefectCaseRefs    = meta.KisaDefectCaseRefs
	base.AdditionalReviewItems = toRawJSON(meta.AdditionalReviewItems)
	base.ManualCheckAreas      = toRawJSON(meta.ManualCheckAreas)
	base.AutomationCoverage    = meta.AutomationCoverage
	base.AlternativeControls   = meta.AlternativeControls
	base.Deferred               = meta.Deferred
	base.DeferredReason         = meta.DeferredReason

	if meta.Deferred {
		base.Matched = false
		base.Verdict = "skipped"
		base.Observation = fmt.Sprintf("[보류] %s", meta.DeferredReason)
		return base
	}

	// Parse condition
	if len(meta.Condition) == 0 {
		base.Observation = "조건 미정의 (manual_meta.condition 없음)"
		base.Verdict = "skipped"
		return base
	}
	var cond map[string]any
	if err := json.Unmarshal(meta.Condition, &cond); err != nil {
		base.Observation = fmt.Sprintf("조건 파싱 오류: %v", err)
		base.Verdict = "skipped"
		return base
	}

	op, _ := cond["operator"].(string)
	log.Printf("[finding] evaluating %s operator=%s", rule.RuleID, op)

	// reportOperators always produce informational output regardless of matched.
	// They contribute verdict="준수" and never trigger 검토필요.
	reportOperators := map[string]bool{
		"inventory_report":               true,
		"traffic_graph_report":           true,
		"external_dependency_report":     true,
		"change_activity_report":         true,
		"default_deny_coverage_report":   true,
		"cross_ns_traffic_control_report": true,
		"external_domain_traffic_report": true,
	}

	var result grc.RuleResult
	switch op {
	case "inventory_report":
		result = evalInventoryReport(base, snap)
	case "traffic_graph_report":
		result = evalTrafficGraphReport(base, snap)
	case "external_dependency_report":
		result = evalExternalDependencyReport(base, snap)
	case "any_owner_indicator_exists":
		result = evalOwnerIndicatorExists(base, snap, cond)
	case "change_activity_report":
		result = evalChangeActivityReport(base, snap)
	case "in_set":
		result = evalInSet(base, snap, cond)
	case "orphan_serviceaccount":
		result = evalOrphanServiceAccount(base, snap)
	case "regex_match":
		result = evalRegexMatch(base, snap, cond)
	case "any_of":
		result = evalAnyOfPrivileged(base, snap, cond)
	case "any_dangerous_verb":
		result = evalAnyDangerousVerb(base, snap, cond)
	case "default_deny_coverage_report":
		result = evalDefaultDenyCoverage(base, snap)
	case "daemonset_exists":
		result = evalDaemonsetExists(base, snap, cond)
	case "cross_ns_traffic_control_report":
		result = evalCrossNSTrafficControl(base, snap)
	case "egress_policy_applied":
		result = evalEgressPolicyApplied(base, snap)
	case "external_domain_traffic_report":
		result = evalExternalDomainTraffic(base, snap)
	case "field_non_empty":
		result = evalFieldNonEmpty(base, snap, cond)
	case "label_value_in":
		result = evalLabelValueIn(base, snap, cond)
	case "namespace_env_homogeneous":
		result = evalNamespaceEnvHomogeneous(base, snap)
	case "all_of":
		result = evalAllOf(base, snap, cond)
	case "field_equals":
		result = evalFieldEquals(base, snap, cond)
	case "kubelet_version_check":
		result = evalKubeletVersionCheck(base, snap)
	case "tag_mutable_check":
		result = evalTagMutableCheck(base, snap, cond)
	case "digest_present":
		result = evalDigestPresent(base, snap)
	case "cve_vulnerability_check":
		result = evalCVEVulnerabilityCheck(base, snap, cond)
	case "prod_shell_exec_detection":
		result = findingProdShellExec(base, snap, cond)
	default:
		base.Observation = fmt.Sprintf("미지원 operator: %s", op)
		base.Verdict = "skipped"
		return base
	}

	if reportOperators[op] {
		result.Verdict = "준수"
		return result
	}
	return deriveManualVerdict(result)
}

// deriveManualVerdict maps verdict_type + matched → verdict for manual rules.
//
//   potential_finding  + matched=true  → 검토필요
//   potential_finding  + matched=false → 준수
//   compliant_indicator + matched=true → 준수
//   compliant_indicator + matched=false → 검토필요
//   needs_review       (any)           → 검토필요
//   additional_evidence (any)          → 준수  (informational only)
func deriveManualVerdict(rr grc.RuleResult) grc.RuleResult {
	switch rr.VerdictType {
	case "potential_finding":
		if rr.Matched {
			rr.Verdict = "검토필요"
		} else {
			rr.Verdict = "준수"
		}
	case "compliant_indicator":
		if rr.Matched {
			rr.Verdict = "준수"
		} else {
			rr.Verdict = "검토필요"
		}
	case "needs_review":
		rr.Verdict = "검토필요"
	case "additional_evidence":
		rr.Verdict = "준수"
	default:
		// Unknown or empty verdict_type: treat as informational.
		rr.Verdict = "준수"
	}
	return rr
}

// EvaluateFindings is kept for backward compatibility.
// Deprecated: Use EvaluateManualRules instead.
func EvaluateFindings(rules []Rule, snap *ClusterSnapshot) []grc.RuleResult {
	return EvaluateManualRules(rules, snap)
}

// ─────────────────────────────────────────────
// F-1.2.1-K8S-01: 클러스터 자산 인벤토리
// ─────────────────────────────────────────────

func evalInventoryReport(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	nsCount := len(snap.Namespaces)
	podCount := len(snap.Pods)
	svcCount := len(snap.Related.Services)
	cmCount := len(snap.Related.ConfigMaps)

	base.Matched = true
	base.Observation = fmt.Sprintf("클러스터 '%s'에서 namespace %d개, Pod %d개, Service %d개, ConfigMap %d개 발견",
		snap.ClusterName, nsCount, podCount, svcCount, cmCount)
	base.Evidence = map[string]any{
		"cluster":   snap.ClusterName,
		"ns_count":  nsCount,
		"pod_count": podCount,
		"svc_count": svcCount,
		"cm_count":  cmCount,
	}
	return base
}

// ─────────────────────────────────────────────
// F-1.2.2-K8S-01: 클러스터 내부 통신 관계 인벤토리
// ─────────────────────────────────────────────

func evalTrafficGraphReport(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	svcCount := len(snap.Related.Services)
	ingCount := len(snap.Related.Ingresses)
	npCount := len(snap.Related.NetworkPolicies)
	edgeCount := svcCount + ingCount // simplified edge count

	base.Matched = true
	base.Observation = fmt.Sprintf("Service %d개, Ingress %d개, NetworkPolicy %d개 발견. 통신 그래프 엣지 %d개",
		svcCount, ingCount, npCount, edgeCount)
	base.Evidence = map[string]any{
		"svc_count":  svcCount,
		"ing_count":  ingCount,
		"np_count":   npCount,
		"edge_count": edgeCount,
	}
	return base
}

// ─────────────────────────────────────────────
// F-1.2.2-K8S-02: 외부 의존성 발견
// ─────────────────────────────────────────────

func evalExternalDependencyReport(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	var extSvcs []string
	for _, svc := range snap.Related.Services {
		svcType := jsonStr(svc, "spec", "type")
		if svcType == "ExternalName" {
			extName := jsonStr(svc, "spec", "externalName")
			svcName := jsonStr(svc, "metadata", "name")
			extSvcs = append(extSvcs, fmt.Sprintf("%s→%s", svcName, extName))
		}
	}

	dnsCount := len(snap.Related.EBPFProcessEvents) // simplified
	domainList := "N/A"
	if len(extSvcs) > 0 {
		domainList = strings.Join(extSvcs, ", ")
	}

	base.Matched = len(extSvcs) > 0 || dnsCount > 0
	base.Observation = fmt.Sprintf("ExternalName Service %d개 발견. 외부 도메인: %s. eBPF에서 외부 도메인 호출 %d회 관찰",
		len(extSvcs), domainList, dnsCount)
	base.Evidence = map[string]any{
		"ext_svc_count": len(extSvcs),
		"domain_list":   domainList,
		"dns_count":     dnsCount,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.1.3-K8S-01: Pod 책임자 정보 부재
// ─────────────────────────────────────────────

func evalOwnerIndicatorExists(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	fields := condStringSlice(cond, "fields")
	if len(fields) == 0 {
		fields = []string{"annotations.owner", "annotations.contact", "labels.team"}
	}

	podTotal := 0
	missingCount := 0
	var missingList []string

	for _, pod := range snap.Pods {
		if isSystemNS(pod.Namespace) {
			continue
		}
		podTotal++

		var labels map[string]any
		_ = json.Unmarshal(pod.Labels, &labels)
		var annotations map[string]any
		_ = json.Unmarshal(pod.Annotations, &annotations)

		found := false
		for _, f := range fields {
			parts := strings.SplitN(f, ".", 2)
			if len(parts) != 2 {
				continue
			}
			var source map[string]any
			switch parts[0] {
			case "annotations":
				source = annotations
			case "labels":
				source = labels
			}
			if source != nil {
				if v, ok := source[parts[1]]; ok && v != nil && strVal(v) != "" {
					found = true
					break
				}
			}
		}
		if !found {
			missingCount++
			if len(missingList) < 10 {
				missingList = append(missingList, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
			}
			base.AffectedResources = append(base.AffectedResources, grc.AffectedResource{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
			})
		}
	}

	base.Matched = missingCount > 0
	listStr := strings.Join(missingList, ", ")
	if missingCount > len(missingList) {
		listStr += fmt.Sprintf(" 외 %d개", missingCount-len(missingList))
	}
	base.Observation = fmt.Sprintf("Pod %d개 중 책임자 정보(owner/contact annotation 또는 team 라벨) 부재 %d개. 목록: %s",
		podTotal, missingCount, listStr)
	base.Evidence = map[string]any{
		"pod_count":     podTotal,
		"missing_count": missingCount,
		"missing_list":  listStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.1.3-K8S-02: 자산 변경 활동 감지
// ─────────────────────────────────────────────

func evalChangeActivityReport(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	// Snapshot-based, no history available → report current state
	base.Matched = true
	base.Observation = fmt.Sprintf("현재 스냅샷 기준 워크로드 %d개 존재. 변경 이력은 스냅샷 비교 필요",
		len(snap.Related.Workloads))
	base.Evidence = map[string]any{
		"workload_count": len(snap.Related.Workloads),
		"created_count":  0,
		"deleted_count":  0,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.5.1-K8S-01: default ServiceAccount 사용 발견
// ─────────────────────────────────────────────

func evalInSet(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	field, _ := cond["field"].(string)
	values := condStringSlice(cond, "values")

	// Parse exception namespaces from finding
	var excNS []string
	if base.RuleID == "F-2.5.1-K8S-01" {
		excNS = []string{"kube-system", "kube-public", "kube-node-lease"}
	}

	var matchedPods []string
	nsDistribution := map[string]int{}
	podCount := 0

	for _, pod := range snap.Pods {
		if containsStr(excNS, pod.Namespace) {
			continue
		}

		var val string
		switch field {
		case "service_account":
			val = pod.ServiceAccount
		}

		for _, v := range values {
			if val == v {
				podCount++
				nsDistribution[pod.Namespace]++
				if len(matchedPods) < 10 {
					matchedPods = append(matchedPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
				}
				base.AffectedResources = append(base.AffectedResources, grc.AffectedResource{
					Kind:      "Pod",
					Name:      pod.Name,
					Namespace: pod.Namespace,
				})
				break
			}
		}
	}

	base.Matched = podCount > 0
	nsDist := formatMap(nsDistribution)
	podList := strings.Join(matchedPods, ", ")
	if podCount > len(matchedPods) {
		podList += fmt.Sprintf(" 외 %d개", podCount-len(matchedPods))
	}

	base.Observation = fmt.Sprintf("Pod %d개가 default SA 사용 중. namespace 분포: %s. 목록: %s",
		podCount, nsDist, podList)
	base.Evidence = map[string]any{
		"pod_count":       podCount,
		"ns_distribution": nsDistribution,
		"pod_list":        podList,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.5.1-K8S-02: 미사용(orphan) ServiceAccount 발견
// ─────────────────────────────────────────────

func evalOrphanServiceAccount(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	// Build set of SA names referenced in bindings
	boundSAs := map[string]bool{}
	for _, rb := range snap.Related.RoleBindings {
		for _, s := range jsonSlice(rb, "subjects") {
			sm := toMap(s)
			if sm != nil && strVal(sm["kind"]) == "ServiceAccount" {
				key := strVal(sm["namespace"]) + "/" + strVal(sm["name"])
				boundSAs[key] = true
			}
		}
	}
	for _, crb := range snap.Related.ClusterRoleBindings {
		for _, s := range jsonSlice(crb, "subjects") {
			sm := toMap(s)
			if sm != nil && strVal(sm["kind"]) == "ServiceAccount" {
				key := strVal(sm["namespace"]) + "/" + strVal(sm["name"])
				boundSAs[key] = true
			}
		}
	}

	saTotal := len(snap.Related.ServiceAccounts)
	orphanCount := 0
	var orphanList []string
	for _, sa := range snap.Related.ServiceAccounts {
		saName := jsonStr(sa, "metadata", "name")
		saNS := jsonStr(sa, "metadata", "namespace")
		if saName == "default" {
			continue // skip default SA
		}
		key := saNS + "/" + saName
		if !boundSAs[key] {
			orphanCount++
			if len(orphanList) < 10 {
				orphanList = append(orphanList, key)
			}
		}
	}

	base.Matched = orphanCount > 0
	base.Observation = fmt.Sprintf("ServiceAccount %d개 중 %d개가 어떤 RoleBinding/ClusterRoleBinding에도 연결되지 않음",
		saTotal, orphanCount)
	base.Evidence = map[string]any{
		"sa_total":     saTotal,
		"orphan_count": orphanCount,
		"orphan_list":  orphanList,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.5.2-K8S-01/02: 추측 가능한 명칭의 SA
// ─────────────────────────────────────────────

func evalRegexMatch(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	field, _ := cond["field"].(string)
	pattern, _ := cond["pattern"].(string)
	re, err := regexp.Compile(pattern)
	if err != nil {
		base.Observation = fmt.Sprintf("regex 컴파일 오류: %v", err)
		return base
	}

	var matchedItems []string
	matchCount := 0

	if field == "name" {
		// Match against ServiceAccount names
		for _, sa := range snap.Related.ServiceAccounts {
			saName := jsonStr(sa, "metadata", "name")
			saNS := jsonStr(sa, "metadata", "namespace")
			if isSystemNS(saNS) {
				continue
			}
			if re.MatchString(saName) {
				matchCount++
				if len(matchedItems) < 10 {
					matchedItems = append(matchedItems, saNS+"/"+saName)
				}
			}
		}
	}

	base.Matched = matchCount > 0
	saList := strings.Join(matchedItems, ", ")
	if matchCount > len(matchedItems) {
		saList += fmt.Sprintf(" 외 %d개", matchCount-len(matchedItems))
	}
	base.Observation = fmt.Sprintf("SA %d개의 이름이 패턴(%s)에 매칭. 목록: %s",
		matchCount, pattern, saList)
	base.Evidence = map[string]any{
		"match_count": matchCount,
		"sa_list":     saList,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.5.5-K8S-01: 클러스터 최고 권한 보유 SA
// ─────────────────────────────────────────────

func evalAnyOfPrivileged(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	var clusterAdminSAs, wildcardSAs, secretFullSAs []string

	// Check ClusterRoleBindings
	for _, crb := range snap.Related.ClusterRoleBindings {
		roleRef := jsonMap(crb, "roleRef")
		roleName := strVal(roleRef["name"])
		subjects := jsonSlice(crb, "subjects")

		for _, s := range subjects {
			sm := toMap(s)
			if sm == nil || strVal(sm["kind"]) != "ServiceAccount" {
				continue
			}
			saKey := strVal(sm["namespace"]) + "/" + strVal(sm["name"])

			if roleName == "cluster-admin" {
				clusterAdminSAs = appendUnique(clusterAdminSAs, saKey)
			}

			// Check the ClusterRole for wildcard/secrets
			for _, cr := range snap.Related.ClusterRoles {
				if jsonStr(cr, "metadata", "name") != roleName {
					continue
				}
				for _, r := range jsonSlice(cr, "rules") {
					rm := toMap(r)
					verbs := toStringSlice(rm["verbs"])
					resources := toStringSlice(rm["resources"])
					apiGroups := toStringSlice(rm["apiGroups"])

					if containsStr(verbs, "*") && containsStr(resources, "*") {
						wildcardSAs = appendUnique(wildcardSAs, saKey)
					}
					if containsStr(resources, "secrets") && (containsStr(apiGroups, "") || containsStr(apiGroups, "*")) {
						for _, sv := range []string{"get", "list", "watch", "*"} {
							if containsStr(verbs, sv) {
								secretFullSAs = appendUnique(secretFullSAs, saKey)
								break
							}
						}
					}
				}
			}
		}
	}

	totalFound := len(clusterAdminSAs) + len(wildcardSAs) + len(secretFullSAs)
	base.Matched = totalFound > 0
	base.Observation = fmt.Sprintf("특수권한 보유 SA 발견 — cluster-admin 바인딩: %s, 와일드카드 권한: %s, 전체 Secret 접근: %s",
		saListOrNone(clusterAdminSAs), saListOrNone(wildcardSAs), saListOrNone(secretFullSAs))
	base.Evidence = map[string]any{
		"cluster_admin_sas": clusterAdminSAs,
		"wildcard_sas":      wildcardSAs,
		"secret_full_sas":   secretFullSAs,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.5.5-K8S-02: 위험 RBAC 권한 보유 SA
// ─────────────────────────────────────────────

func evalAnyDangerousVerb(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	type dangerPattern struct {
		Name     string
		Resource string
		Verbs    []string
	}
	patterns := []dangerPattern{
		{"pod_exec", "pods/exec", []string{"create", "*"}},
		{"secret_write", "secrets", []string{"create", "update", "patch", "*"}},
		{"rbac_escalate", "clusterroles", []string{"escalate"}},
		{"impersonate", "users", []string{"impersonate"}},
	}

	// Exclude wildcard SAs already flagged by F-2.5.5-K8S-01
	wildcardSAs := identifyWildcardSAs(snap)

	findings := map[string][]string{}
	allRoles := collectAllRBACRules(snap)

	for _, p := range patterns {
		for _, rr := range allRoles {
			if wildcardSAs[rr.saKey] {
				continue
			}
			hasVerb := false
			hasResource := false
			for _, v := range p.Verbs {
				if containsStr(rr.verbs, v) || containsStr(rr.verbs, "*") {
					hasVerb = true
					break
				}
			}
			if containsStr(rr.resources, p.Resource) || containsStr(rr.resources, "*") {
				hasResource = true
			}
			if hasVerb && hasResource {
				findings[p.Name] = appendUnique(findings[p.Name], rr.saKey)
			}
		}
	}

	totalFound := 0
	var summaryParts []string
	for pName, sas := range findings {
		totalFound += len(sas)
		summaryParts = append(summaryParts, fmt.Sprintf("%s: %s", pName, strings.Join(sas, ", ")))
	}

	base.Matched = totalFound > 0
	summary := "없음"
	if len(summaryParts) > 0 {
		summary = strings.Join(summaryParts, "; ")
	}
	base.Observation = fmt.Sprintf("위험 권한 조합 보유 SA 발견 — %s", summary)
	base.Evidence = map[string]any{
		"dangerous_pattern_summary": summary,
		"details":                   findings,
		"wildcard_sa_excluded":      len(wildcardSAs),
	}
	return base
}

// identifyWildcardSAs returns SA keys that have cluster-admin binding or
// wildcard verbs+resources (already flagged by F-2.5.5-K8S-01).
func identifyWildcardSAs(snap *ClusterSnapshot) map[string]bool {
	wildcards := map[string]bool{}
	for _, crb := range snap.Related.ClusterRoleBindings {
		roleRef := jsonMap(crb, "roleRef")
		roleName := strVal(roleRef["name"])
		subjects := jsonSlice(crb, "subjects")

		for _, s := range subjects {
			sm := toMap(s)
			if sm == nil || strVal(sm["kind"]) != "ServiceAccount" {
				continue
			}
			saKey := strVal(sm["namespace"]) + "/" + strVal(sm["name"])

			if roleName == "cluster-admin" {
				wildcards[saKey] = true
				continue
			}
			for _, cr := range snap.Related.ClusterRoles {
				if jsonStr(cr, "metadata", "name") != roleName {
					continue
				}
				for _, r := range jsonSlice(cr, "rules") {
					rm := toMap(r)
					verbs := toStringSlice(rm["verbs"])
					resources := toStringSlice(rm["resources"])
					if containsStr(verbs, "*") && containsStr(resources, "*") {
						wildcards[saKey] = true
					}
				}
			}
		}
	}
	return wildcards
}

// ─────────────────────────────────────────────
// F-2.6.1-K8S-01: NetworkPolicy 적용 현황
// ─────────────────────────────────────────────

func evalDefaultDenyCoverage(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	nsTotal := 0
	appliedCount := 0
	var missingNS []string

	// Build set of namespaces that have default-deny
	nsWithDeny := map[string]bool{}
	for _, np := range snap.Related.NetworkPolicies {
		npNS := jsonStr(np, "metadata", "namespace")
		podSelector := jsonMap(np, "spec", "podSelector")
		matchLabels := jsonMap(podSelector, "matchLabels")
		policyTypes := toStringSlice(jsonMap(np, "spec")["policyTypes"])

		isEmptySelector := len(matchLabels) == 0 && len(jsonSlice(podSelector, "matchExpressions")) == 0
		hasIngress := containsStr(policyTypes, "Ingress")
		hasEgress := containsStr(policyTypes, "Egress")

		if isEmptySelector && (hasIngress || hasEgress) {
			ingressRules := jsonSlice(np, "spec", "ingress")
			egressRules := jsonSlice(np, "spec", "egress")
			if len(ingressRules) == 0 || len(egressRules) == 0 {
				nsWithDeny[npNS] = true
			}
		}
	}

	for _, ns := range snap.Namespaces {
		if isSystemNS(ns) {
			continue
		}
		nsTotal++
		if nsWithDeny[ns] {
			appliedCount++
		} else {
			missingNS = append(missingNS, ns)
		}
	}

	pct := 0
	if nsTotal > 0 {
		pct = appliedCount * 100 / nsTotal
	}

	base.Matched = true
	missingList := strings.Join(missingNS, ", ")
	if len(missingNS) == 0 {
		missingList = "없음"
	}
	base.Observation = fmt.Sprintf("전체 namespace %d개 중 default-deny NetworkPolicy 적용 %d개 (%d%%). 미적용 namespace: %s",
		nsTotal, appliedCount, pct, missingList)
	base.Evidence = map[string]any{
		"ns_total":       nsTotal,
		"applied_count":  appliedCount,
		"percentage":     pct,
		"missing_ns_list": missingNS,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.6.1-K8S-02: CNI NetworkPolicy 강제 상태
// ─────────────────────────────────────────────

func evalDaemonsetExists(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	targetNS, _ := cond["namespace"].(string)
	namePatterns := condStringSlice(cond, "name_patterns")
	if len(namePatterns) == 0 {
		namePatterns = []string{"calico-node", "cilium", "calico-kube-controllers"}
	}

	var foundNames []string
	for _, wl := range snap.Related.Workloads {
		wlName := jsonStr(wl, "metadata", "name")
		wlNS := jsonStr(wl, "metadata", "namespace")
		if targetNS != "" && wlNS != targetNS {
			continue
		}
		for _, pat := range namePatterns {
			if strings.Contains(wlName, pat) {
				foundNames = append(foundNames, fmt.Sprintf("%s/%s", wlNS, wlName))
				break
			}
		}
	}

	status := "미발견"
	if len(foundNames) > 0 {
		status = strings.Join(foundNames, ", ")
	}

	base.Matched = true // always report
	base.Observation = fmt.Sprintf("kube-system namespace에서 NetworkPolicy 강제 CNI(Calico/Cilium) DaemonSet %s", status)
	base.Evidence = map[string]any{
		"found_status": status,
		"found_names":  foundNames,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.6.1-K8S-03: Cross-namespace 통신 통제 현황
// ─────────────────────────────────────────────

func evalCrossNSTrafficControl(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	nsWithIngress := map[string]bool{}
	for _, np := range snap.Related.NetworkPolicies {
		npNS := jsonStr(np, "metadata", "namespace")
		policyTypes := toStringSlice(jsonMap(np, "spec")["policyTypes"])
		if containsStr(policyTypes, "Ingress") || containsStr(policyTypes, "Egress") {
			nsWithIngress[npNS] = true
		}
	}

	blockedCount := 0
	openCount := 0
	for _, ns := range snap.Namespaces {
		if isSystemNS(ns) {
			continue
		}
		if nsWithIngress[ns] {
			blockedCount++
		} else {
			openCount++
		}
	}

	base.Matched = true
	base.Observation = fmt.Sprintf("NetworkPolicy로 cross-namespace 통신 차단된 namespace %d개, 차단 없음 %d개",
		blockedCount, openCount)
	base.Evidence = map[string]any{
		"blocked_count": blockedCount,
		"open_count":    openCount,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.6.7-K8S-01: Pod egress 통제 현황
// ─────────────────────────────────────────────

func evalEgressPolicyApplied(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	// Find namespaces with egress policies
	nsWithEgress := map[string]bool{}
	for _, np := range snap.Related.NetworkPolicies {
		npNS := jsonStr(np, "metadata", "namespace")
		policyTypes := toStringSlice(jsonMap(np, "spec")["policyTypes"])
		if containsStr(policyTypes, "Egress") {
			nsWithEgress[npNS] = true
		}
	}

	missingCount := 0
	var podList []string
	for _, pod := range snap.Pods {
		if isSystemNS(pod.Namespace) {
			continue
		}
		if !nsWithEgress[pod.Namespace] {
			missingCount++
			if len(podList) < 10 {
				podList = append(podList, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
			}
			base.AffectedResources = append(base.AffectedResources, grc.AffectedResource{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
			})
		}
	}

	podListStr := strings.Join(podList, ", ")
	if missingCount > len(podList) {
		podListStr += fmt.Sprintf(" 외 %d개", missingCount-len(podList))
	}

	base.Matched = missingCount > 0
	base.Observation = fmt.Sprintf("운영 Pod 중 egress NetworkPolicy 미적용 %d개. 목록: %s",
		missingCount, podListStr)
	base.Evidence = map[string]any{
		"missing_count": missingCount,
		"pod_list":      podListStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.6.7-K8S-02: 실제 외부 도메인 접속 관찰 (eBPF)
// ─────────────────────────────────────────────

func evalExternalDomainTraffic(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	eventCount := len(snap.Related.EBPFProcessEvents)

	base.Matched = eventCount > 0
	base.Observation = fmt.Sprintf("eBPF 프로세스 이벤트 %d건 관찰 (상세 분석 필요)", eventCount)
	base.Evidence = map[string]any{
		"event_count":         eventCount,
		"domain_distribution": "eBPF 데이터 기반 분석 필요",
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.7.1-K8S-01: Ingress TLS 적용 현황
// F-2.10.5-K8S-01: 외부 공개 Ingress TLS 현황 (scope=external_only)
// ─────────────────────────────────────────────

func evalFieldNonEmpty(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	field, _ := cond["field"].(string)

	if field == "spec.tls" {
		scope, _ := cond["scope"].(string)
		return evalIngressTLSReport(base, snap, scope)
	}

	base.Observation = fmt.Sprintf("미지원 field_non_empty 필드: %s", field)
	return base
}

func evalIngressTLSReport(base grc.RuleResult, snap *ClusterSnapshot, scope string) grc.RuleResult {
	totalCount := 0
	tlsCount := 0
	var missingList []string

	for _, ing := range snap.Related.Ingresses {
		if scope == "external_only" && !isExternalIngress(ing) {
			continue
		}
		totalCount++
		ingName := jsonStr(ing, "metadata", "name")
		ingNS := jsonStr(ing, "metadata", "namespace")
		tlsSlice := jsonSlice(ing, "spec", "tls")
		if len(tlsSlice) > 0 {
			tlsCount++
		} else {
			missingList = append(missingList, fmt.Sprintf("%s/%s", ingNS, ingName))
		}
	}

	plaintextCount := totalCount - tlsCount
	missingStr := strings.Join(missingList, ", ")
	if len(missingList) == 0 {
		missingStr = "없음"
	}

	scopeLabel := "Ingress"
	if scope == "external_only" {
		scopeLabel = "외부 공개 Ingress"
	}

	base.Matched = plaintextCount > 0
	base.Observation = fmt.Sprintf("%s %d개 중 TLS 설정 %d개, 미설정 %d개. 미설정 목록: %s",
		scopeLabel, totalCount, tlsCount, plaintextCount, missingStr)
	base.Evidence = map[string]any{
		"total_count":     totalCount,
		"tls_count":       tlsCount,
		"plaintext_count": plaintextCount,
		"missing_list":    missingStr,
	}
	return base
}

// isExternalIngress returns true if the Ingress is externally exposed.
// ALB scheme annotation with "internal" or ingressClassName containing "internal" → not external.
// Default is external (conservative: assume exposed unless proven internal).
func isExternalIngress(ing map[string]any) bool {
	annotations := jsonMap(ing, "metadata", "annotations")
	// AWS ALB controller: alb.ingress.kubernetes.io/scheme=internal
	scheme := strVal(annotations["alb.ingress.kubernetes.io/scheme"])
	if strings.EqualFold(scheme, "internal") {
		return false
	}
	// NLB: service.beta.kubernetes.io/aws-load-balancer-scheme
	nlbScheme := strVal(annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"])
	if strings.EqualFold(nlbScheme, "internal") {
		return false
	}
	// IngressClass name containing "internal"
	ingressClass := jsonStr(ing, "spec", "ingressClassName")
	if ingressClass != "" && strings.Contains(strings.ToLower(ingressClass), "internal") {
		return false
	}
	return true
}

// ─────────────────────────────────────────────
// F-2.8.3-K8S-01: 환경 라벨 적용 현황
// ─────────────────────────────────────────────

func evalLabelValueIn(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	field, _ := cond["field"].(string)
	values := condStringSlice(cond, "values")

	if field == "labels.env" {
		return evalWorkloadEnvLabelReport(base, snap, values)
	}

	base.Observation = fmt.Sprintf("미지원 label_value_in 필드: %s", field)
	return base
}

func evalWorkloadEnvLabelReport(base grc.RuleResult, snap *ClusterSnapshot, values []string) grc.RuleResult {
	totalCount := 0
	appliedCount := 0
	missingNS := map[string]bool{}

	for _, pod := range snap.Pods {
		if isSystemNS(pod.Namespace) {
			continue
		}
		totalCount++
		var labels map[string]any
		_ = json.Unmarshal(pod.Labels, &labels)
		envVal := strVal(labels["env"])
		found := false
		for _, v := range values {
			if envVal == v {
				found = true
				break
			}
		}
		if found {
			appliedCount++
		} else {
			missingNS[pod.Namespace] = true
		}
	}

	pct := 0
	if totalCount > 0 {
		pct = appliedCount * 100 / totalCount
	}

	var missingNSList []string
	for ns := range missingNS {
		missingNSList = append(missingNSList, ns)
	}
	missingStr := strings.Join(missingNSList, ", ")
	if len(missingNSList) == 0 {
		missingStr = "없음"
	}

	base.Matched = true
	base.Observation = fmt.Sprintf("Pod %d개 중 env 라벨 적용 %d개 (%d%%). 미적용 namespace: %s",
		totalCount, appliedCount, pct, missingStr)
	base.Evidence = map[string]any{
		"total_count":    totalCount,
		"applied_count":  appliedCount,
		"percentage":     pct,
		"missing_ns":     missingStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.8.3-K8S-02: 환경 혼재 namespace 발견
// ─────────────────────────────────────────────

func evalNamespaceEnvHomogeneous(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	nsEnvs := map[string]map[string]int{} // ns → env → count

	for _, pod := range snap.Pods {
		if isSystemNS(pod.Namespace) {
			continue
		}
		var labels map[string]any
		_ = json.Unmarshal(pod.Labels, &labels)
		envVal := strVal(labels["env"])
		if envVal == "" {
			envVal = "(미설정)"
		}
		if nsEnvs[pod.Namespace] == nil {
			nsEnvs[pod.Namespace] = map[string]int{}
		}
		nsEnvs[pod.Namespace][envVal]++
	}

	mixedCount := 0
	var nsEnvDistribution []string
	for ns, envMap := range nsEnvs {
		if len(envMap) > 1 {
			mixedCount++
			var parts []string
			for env, count := range envMap {
				parts = append(parts, fmt.Sprintf("%s=%d", env, count))
			}
			nsEnvDistribution = append(nsEnvDistribution, fmt.Sprintf("%s:[%s]", ns, strings.Join(parts, ",")))
		}
	}

	distStr := strings.Join(nsEnvDistribution, "; ")
	if len(nsEnvDistribution) == 0 {
		distStr = "없음"
	}

	base.Matched = mixedCount > 0
	base.Observation = fmt.Sprintf("namespace %d개에서 env 라벨이 다른 Pod 공존. 상세: %s",
		mixedCount, distStr)
	base.Evidence = map[string]any{
		"mixed_count":         mixedCount,
		"ns_env_distribution": distStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.10.5-K8S-02: ExternalName Service 평문 호출
// ─────────────────────────────────────────────

func evalAllOf(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	conditions, _ := cond["conditions"].([]any)
	if len(conditions) < 2 {
		base.Observation = "all_of 조건 불충분"
		return base
	}

	// Check ExternalName + http:// pattern
	first := toMap(conditions[0])
	if first != nil && strVal(first["field"]) == "spec.type" && strVal(first["equals"]) == "ExternalName" {
		return findingExternalNamePlaintext(base, snap)
	}

	base.Observation = "미지원 all_of 조합"
	return base
}

// ─────────────────────────────────────────────
// F-2.10.3-K8S-03: NodePort 노출 현황
// ─────────────────────────────────────────────

func evalFieldEquals(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	field, _ := cond["field"].(string)
	value, _ := cond["value"].(string)

	if field == "spec.type" && value == "NodePort" {
		return evalNodePortReport(base, snap)
	}

	base.Observation = fmt.Sprintf("미지원 field_equals: %s=%s", field, value)
	return base
}

func evalNodePortReport(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	count := 0
	var nodeportList []string

	for _, svc := range snap.Related.Services {
		svcType := jsonStr(svc, "spec", "type")
		if svcType == "NodePort" {
			count++
			svcName := jsonStr(svc, "metadata", "name")
			svcNS := jsonStr(svc, "metadata", "namespace")
			nodeportList = append(nodeportList, fmt.Sprintf("%s/%s", svcNS, svcName))
		}
	}

	npStr := strings.Join(nodeportList, ", ")
	if len(nodeportList) == 0 {
		npStr = "없음"
	}

	base.Matched = count > 0
	base.Observation = fmt.Sprintf("type=NodePort Service %d개 발견. 목록: %s", count, npStr)
	base.Evidence = map[string]any{
		"count":         count,
		"nodeport_list": npStr,
	}
	return base
}

func findingExternalNamePlaintext(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	totalCount := 0
	plaintextCount := 0
	var list []string

	for _, svc := range snap.Related.Services {
		svcType := jsonStr(svc, "spec", "type")
		if svcType != "ExternalName" {
			continue
		}
		totalCount++
		extName := jsonStr(svc, "spec", "externalName")
		svcName := jsonStr(svc, "metadata", "name")
		svcNS := jsonStr(svc, "metadata", "namespace")

		if strings.HasPrefix(extName, "http://") {
			plaintextCount++
			list = append(list, fmt.Sprintf("%s/%s→%s", svcNS, svcName, extName))
		}
	}

	listStr := strings.Join(list, ", ")
	if len(list) == 0 {
		listStr = "없음"
	}

	base.Matched = plaintextCount > 0
	base.Observation = fmt.Sprintf("ExternalName Service %d개 중 http:// 시작 endpoint %d개. 목록: %s",
		totalCount, plaintextCount, listStr)
	base.Evidence = map[string]any{
		"total_count":     totalCount,
		"plaintext_count": plaintextCount,
		"list":            listStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.10.8-K8S-01: Node Kubernetes 버전 현황
// ─────────────────────────────────────────────

func evalKubeletVersionCheck(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	totalCount := len(snap.Related.Nodes)
	versionDist := map[string]int{}
	eolCount := 0

	for _, node := range snap.Related.Nodes {
		status := jsonMap(node, "status")
		nodeInfo := jsonMap(status, "nodeInfo")
		version := strVal(nodeInfo["kubeletVersion"])
		if version == "" {
			version = "(unknown)"
		}
		versionDist[version]++
	}

	var distParts []string
	for v, c := range versionDist {
		distParts = append(distParts, fmt.Sprintf("%s=%d", v, c))
	}

	distStr := strings.Join(distParts, ", ")
	if len(distParts) == 0 {
		distStr = "N/A"
	}

	base.Matched = true
	base.Observation = fmt.Sprintf("Node %d개의 kubelet 버전 분포: %s. EOL 버전 노드: %d개",
		totalCount, distStr, eolCount)
	base.Evidence = map[string]any{
		"total_count":          totalCount,
		"version_distribution": versionDist,
		"eol_count":            eolCount,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.10.8-K8S-02: 이미지 태그 안정성 현황
// ─────────────────────────────────────────────

func evalTagMutableCheck(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	mutablePatterns := condStringSlice(cond, "mutable_patterns")
	if len(mutablePatterns) == 0 {
		mutablePatterns = []string{"latest", "stable", "prod", "main", "master"}
	}

	totalCount := 0
	mutableCount := 0
	var mutableList []string
	affectedPods := map[string]bool{} // dedup

	for _, pod := range snap.Pods {
		if isSystemNS(pod.Namespace) {
			continue
		}
		var containers []any
		_ = json.Unmarshal(pod.Containers, &containers)
		for _, c := range containers {
			cm := toMap(c)
			if cm == nil {
				continue
			}
			image := strVal(cm["image"])
			totalCount++

			tag := extractImageTag(image)
			for _, mp := range mutablePatterns {
				if tag == mp || tag == "" {
					mutableCount++
					if len(mutableList) < 10 {
						mutableList = append(mutableList, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, image))
					}
					podKey := pod.Namespace + "/" + pod.Name
					if !affectedPods[podKey] {
						affectedPods[podKey] = true
						base.AffectedResources = append(base.AffectedResources, grc.AffectedResource{
							Kind:      "Pod",
							Name:      pod.Name,
							Namespace: pod.Namespace,
						})
					}
					break
				}
			}
		}
	}

	fixedCount := totalCount - mutableCount
	mutableStr := strings.Join(mutableList, ", ")
	if len(mutableList) == 0 {
		mutableStr = "없음"
	}

	base.Matched = mutableCount > 0
	base.Observation = fmt.Sprintf("Pod %d개 중 mutable 태그(latest, stable 등) 사용 %d개, 고정 태그 %d개. 목록: %s",
		totalCount, mutableCount, fixedCount, mutableStr)
	base.Evidence = map[string]any{
		"total_count":   totalCount,
		"mutable_count": mutableCount,
		"fixed_count":   fixedCount,
		"mutable_list":  mutableStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.10.8-K8S-03: 이미지 디지스트 고정 현황
// ─────────────────────────────────────────────

func evalDigestPresent(base grc.RuleResult, snap *ClusterSnapshot) grc.RuleResult {
	totalCount := 0
	missingCount := 0
	var list []string
	affectedPods := map[string]bool{} // dedup

	for _, pod := range snap.Pods {
		if isSystemNS(pod.Namespace) {
			continue
		}
		var containers []any
		_ = json.Unmarshal(pod.Containers, &containers)
		for _, c := range containers {
			cm := toMap(c)
			if cm == nil {
				continue
			}
			totalCount++
			digest := strVal(cm["image_digest"])
			image := strVal(cm["image"])
			if digest == "" && !strings.Contains(image, "@sha256:") {
				missingCount++
				if len(list) < 10 {
					list = append(list, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, image))
				}
				podKey := pod.Namespace + "/" + pod.Name
				if !affectedPods[podKey] {
					affectedPods[podKey] = true
					base.AffectedResources = append(base.AffectedResources, grc.AffectedResource{
						Kind:      "Pod",
						Name:      pod.Name,
						Namespace: pod.Namespace,
					})
				}
			}
		}
	}

	listStr := strings.Join(list, ", ")
	if len(list) == 0 {
		listStr = "없음"
	}

	base.Matched = missingCount > 0
	base.Observation = fmt.Sprintf("Pod %d개 중 image_digest 빈 값 %d개. 목록: %s",
		totalCount, missingCount, listStr)
	base.Evidence = map[string]any{
		"total_count":   totalCount,
		"missing_count": missingCount,
		"list":          listStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.10.8-K8S-04: 실행 중 이미지 알려진 취약점(CVE) 현황
// ─────────────────────────────────────────────

func evalCVEVulnerabilityCheck(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	minSeverity := "HIGH"
	if v, ok := cond["min_severity"].(string); ok {
		minSeverity = v
	}
	sevWeight := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	minWeight := sevWeight[minSeverity]

	vulns := snap.Related.ImageVulnerabilities
	if len(vulns) == 0 {
		// Collect digests from pod containers
		digestCount := 0
		for _, pod := range snap.Pods {
			var containers []map[string]any
			_ = json.Unmarshal(pod.Containers, &containers)
			for _, c := range containers {
				if d := strVal(c["image_digest"]); d != "" {
					digestCount++
				}
			}
		}
		base.Matched = false
		base.Observation = fmt.Sprintf("CVE 스캔 데이터 미제공. image_digest 보유 컨테이너 %d개 (스캔 연동 시 점검 가능)", digestCount)
		base.Evidence = map[string]any{"digest_count": digestCount, "cve_data_provided": false}
		return base
	}

	// Count CVEs by severity
	matchedCount := 0
	var critList []string
	for _, v := range vulns {
		sev := strings.ToUpper(strVal(v["severity"]))
		w := sevWeight[sev]
		if w >= minWeight {
			matchedCount++
			cveID := strVal(v["cve_id"])
			digest := strVal(v["image_digest"])
			if len(critList) < 10 {
				critList = append(critList, fmt.Sprintf("%s(%s, %s)", cveID, sev, digest[:min(16, len(digest))]))
			}
		}
	}

	listStr := strings.Join(critList, ", ")
	if len(critList) == 0 {
		listStr = "없음"
	}

	base.Matched = matchedCount > 0
	base.Observation = fmt.Sprintf("전체 CVE %d건 중 %s 이상 %d건. 상위: %s",
		len(vulns), minSeverity, matchedCount, listStr)
	base.Evidence = map[string]any{
		"total_cves":    len(vulns),
		"matched_count": matchedCount,
		"min_severity":  minSeverity,
		"top_list":      listStr,
	}
	return base
}

// ─────────────────────────────────────────────
// F-2.11.3-K8S-01: 운영 환경 Shell 활동 관찰
// ─────────────────────────────────────────────

func findingProdShellExec(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	binaryPatterns := condStringSlice(cond, "binary_patterns")
	if len(binaryPatterns) == 0 {
		binaryPatterns = []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/bin/zsh"}
	}

	count := 0
	var events []string

	for _, evt := range snap.Related.EBPFProcessEvents {
		binary := jsonStr(evt, "binary")
		podName := jsonStr(evt, "pod_name")
		ns := jsonStr(evt, "namespace")

		for _, bp := range binaryPatterns {
			if binary == bp || strings.HasSuffix(binary, bp) {
				count++
				if len(events) < 5 {
					events = append(events, fmt.Sprintf("%s/%s: %s", ns, podName, binary))
				}
				break
			}
		}
	}

	eventsStr := strings.Join(events, "; ")
	if len(events) == 0 {
		eventsStr = "없음"
	}

	base.Matched = count > 0
	base.Observation = fmt.Sprintf("env=prod namespace Pod에서 shell exec 활동 %d건. 상세: %s",
		count, eventsStr)
	base.Evidence = map[string]any{
		"count":  count,
		"events": eventsStr,
	}
	return base
}

// ─────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────

func isSystemNS(ns string) bool {
	return ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease"
}

func condStringSlice(cond map[string]any, key string) []string {
	raw, ok := cond[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, strVal(item))
		}
		return out
	case []string:
		return v
	}
	return nil
}

func appendUnique(ss []string, s string) []string {
	for _, existing := range ss {
		if existing == s {
			return ss
		}
	}
	return append(ss, s)
}

func saListOrNone(ss []string) string {
	if len(ss) == 0 {
		return "없음"
	}
	return strings.Join(ss, ", ")
}

func formatMap(m map[string]int) string {
	if len(m) == 0 {
		return "{}"
	}
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	return strings.Join(parts, ", ")
}

// extractImageTag is defined in pod_graph_eval_rules.go (reused)

type rbacRuleEntry struct {
	saKey     string
	verbs     []string
	resources []string
	roleKind  string
	roleName  string
}

func collectAllRBACRules(snap *ClusterSnapshot) []rbacRuleEntry {
	var entries []rbacRuleEntry

	// From ClusterRoleBindings
	for _, crb := range snap.Related.ClusterRoleBindings {
		roleRef := jsonMap(crb, "roleRef")
		roleName := strVal(roleRef["name"])
		subjects := jsonSlice(crb, "subjects")

		for _, s := range subjects {
			sm := toMap(s)
			if sm == nil || strVal(sm["kind"]) != "ServiceAccount" {
				continue
			}
			saKey := strVal(sm["namespace"]) + "/" + strVal(sm["name"])

			for _, cr := range snap.Related.ClusterRoles {
				if jsonStr(cr, "metadata", "name") != roleName {
					continue
				}
				for _, r := range jsonSlice(cr, "rules") {
					rm := toMap(r)
					entries = append(entries, rbacRuleEntry{
						saKey:     saKey,
						verbs:     toStringSlice(rm["verbs"]),
						resources: toStringSlice(rm["resources"]),
						roleKind:  "ClusterRole",
						roleName:  roleName,
					})
				}
			}
		}
	}

	// From RoleBindings
	for _, rb := range snap.Related.RoleBindings {
		roleRef := jsonMap(rb, "roleRef")
		roleName := strVal(roleRef["name"])
		roleKind := strVal(roleRef["kind"])
		subjects := jsonSlice(rb, "subjects")

		for _, s := range subjects {
			sm := toMap(s)
			if sm == nil || strVal(sm["kind"]) != "ServiceAccount" {
				continue
			}
			saKey := strVal(sm["namespace"]) + "/" + strVal(sm["name"])

			var roles []map[string]any
			if roleKind == "ClusterRole" {
				roles = snap.Related.ClusterRoles
			} else {
				roles = snap.Related.Roles
			}

			for _, role := range roles {
				if jsonStr(role, "metadata", "name") != roleName {
					continue
				}
				for _, r := range jsonSlice(role, "rules") {
					rm := toMap(r)
					entries = append(entries, rbacRuleEntry{
						saKey:     saKey,
						verbs:     toStringSlice(rm["verbs"]),
						resources: toStringSlice(rm["resources"]),
						roleKind:  roleKind,
						roleName:  roleName,
					})
				}
			}
		}
	}

	return entries
}


