package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// ─────────────────────────────────────────────
// Pod Graph Request / Response
// ─────────────────────────────────────────────

// PodGraphRequest is the API input for Pod-level ISMS-P evaluation.
type PodGraphRequest struct {
	CompanyID        string              `json:"company_id"`
	ClusterName      string              `json:"cluster_name"`
	Pod              map[string]any      `json:"pod"`
	RelatedResources PodRelatedResources `json:"related_resources"`
}

// PodRelatedResources holds K8s resources adjacent to the target Pod.
type PodRelatedResources struct {
	Namespace           map[string]any   `json:"namespace"`
	Services            []map[string]any `json:"services"`
	Ingresses           []map[string]any `json:"ingresses"`
	NetworkPolicies     []map[string]any `json:"network_policies"`
	ConfigMaps          []map[string]any `json:"config_maps"`
	ClusterRoleBindings []map[string]any `json:"cluster_role_bindings"`
	RoleBindings        []map[string]any `json:"role_bindings"`
	ClusterRoles        []map[string]any `json:"cluster_roles"`
	Roles               []map[string]any `json:"roles"`
	ServiceAccounts     []map[string]any `json:"service_accounts"`
	Workloads           []map[string]any `json:"workloads"`
	Secrets             []map[string]any `json:"secrets"`
	Nodes               []map[string]any `json:"nodes"`
	EBPFProcessEvents    []map[string]any `json:"ebpf_process_events"`
	NamespacesInCluster  []map[string]any `json:"namespaces_in_cluster"`
	EKSCluster           map[string]any   `json:"eks_cluster"`
	ImageVulnerabilities []map[string]any `json:"image_vulnerabilities"`
}

// SeverityCount holds pass/fail counts for a severity level.
type SeverityCount struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
}

// PodGraphSummary holds aggregated evaluation statistics.
type PodGraphSummary struct {
	TotalRulesEvaluated int                       `json:"total_rules_evaluated"`
	Pass                int                       `json:"pass"`
	Fail                int                       `json:"fail"`
	Skip                int                       `json:"skip"`
	BySeverity          map[string]*SeverityCount `json:"by_severity"`
}

// PodGraphResult is the evaluation output for a single Pod.
type PodGraphResult struct {
	ID             int64            `json:"id"`
	PodName        string           `json:"pod_name"`
	Namespace      string           `json:"namespace"`
	ClusterName    string           `json:"cluster_name"`
	OverallVerdict string           `json:"overall_verdict"`
	TotalRules     int              `json:"total_rules"`
	Passed         int              `json:"passed"`
	Failed         int              `json:"failed"`
	Skipped        int              `json:"skipped"`
	Summary        *PodGraphSummary `json:"summary,omitempty"`
	RuleResults    []PodRuleResult  `json:"rule_results"`
}

// PodRuleResult holds the verdict for a single Pod-graph rule.
type PodRuleResult struct {
	RuleID            string          `json:"rule_id"`
	Name              string          `json:"name"`
	ISMSPItem         string          `json:"isms_p_item"`
	ISMSPItemName     string          `json:"isms_p_item_name"`
	Severity          string          `json:"severity,omitempty"`
	Verdict           string          `json:"verdict"` // 준수 | 미준수 | skip
	Violations        []grc.Violation `json:"violations,omitempty"`
	MatchedIndicators []string        `json:"matched_indicators,omitempty"`
	FailMessage       string          `json:"fail_message,omitempty"`
	SkipReason        string          `json:"skip_reason,omitempty"`
	Remediation       string          `json:"remediation,omitempty"`
}

// ─────────────────────────────────────────────
// Main Evaluator
// ─────────────────────────────────────────────

// EvaluatePodGraph evaluates all Pod-graph rulesets against the provided K8s resources.
func (s *GRCService) EvaluatePodGraph(ctx context.Context, req PodGraphRequest) (*PodGraphResult, error) {
	rulesets := s.rulesetStore.LoadAllPodRulesets()
	if len(rulesets) == 0 {
		return nil, &GRCError{Code: "NO_POD_RULESETS", Message: "Pod 룰셋이 로드되지 않았습니다", HTTPStatus: 500}
	}

	podName, namespace := extractPodMeta(req.Pod)
	log.Printf("[pod-graph] evaluating pod=%s ns=%s cluster=%s (%d rulesets)",
		podName, namespace, req.ClusterName, len(rulesets))

	result := &PodGraphResult{
		PodName:     podName,
		Namespace:   namespace,
		ClusterName: req.ClusterName,
	}

	for _, rs := range rulesets {
		for _, rule := range rs.Rules {
			// Skip non-k8s_native rules (e.g. manual_evidence, hybrid) in pod graph evaluation
			if rule.JudgmentSource != "" && rule.JudgmentSource != "k8s_native" {
				log.Printf("[pod-graph] skip rule=%s (judgment_source=%s)", rule.RuleID, rule.JudgmentSource)
				continue
			}
			rr := evaluatePodRule(rule, rs.Item.ID, rs.Item.Name, req)
			result.RuleResults = append(result.RuleResults, rr)
			log.Printf("[pod-graph] rule=%s verdict=%s", rule.RuleID, rr.Verdict)
		}
	}

	result.TotalRules = len(result.RuleResults)
	result.OverallVerdict = "준수"
	summary := &PodGraphSummary{
		BySeverity: map[string]*SeverityCount{
			"critical": {},
			"high":     {},
			"medium":   {},
			"low":      {},
		},
	}
	for _, rr := range result.RuleResults {
		summary.TotalRulesEvaluated++
		sev := rr.Severity
		if sev == "" {
			sev = "medium"
		}
		if _, ok := summary.BySeverity[sev]; !ok {
			summary.BySeverity[sev] = &SeverityCount{}
		}
		switch rr.Verdict {
		case "준수":
			result.Passed++
			summary.Pass++
			summary.BySeverity[sev].Pass++
		case "skip":
			result.Skipped++
			summary.Skip++
		default: // 미준수
			result.Failed++
			summary.Fail++
			summary.BySeverity[sev].Fail++
			result.OverallVerdict = "미준수"
		}
	}
	result.Summary = summary

	// Persist to DB
	id, err := s.repo.SavePodGraphEvaluation(ctx,
		req.CompanyID, req.ClusterName, podName, namespace,
		result.OverallVerdict, result.TotalRules, result.Passed, result.Failed, result.Skipped,
		result.RuleResults, result.Summary,
	)
	if err != nil {
		log.Printf("[pod-graph] DB save failed: %v", err)
		// Return result even if DB save fails
	} else {
		result.ID = id
		log.Printf("[pod-graph] saved evaluation id=%d", id)
	}

	return result, nil
}

// ListPodGraphEvaluations returns paginated pod graph evaluation results.
func (s *GRCService) ListPodGraphEvaluations(ctx context.Context, companyID string, page, pageSize int) ([]grc.PodGraphEvalListItem, int, error) {
	return s.repo.ListPodGraphEvaluations(ctx, companyID, page, pageSize)
}

// GetPodGraphEvaluation returns a single pod graph evaluation with full rule_results.
func (s *GRCService) GetPodGraphEvaluation(ctx context.Context, id int64) (*grc.PodGraphEvalListItem, json.RawMessage, error) {
	return s.repo.GetPodGraphEvaluation(ctx, id)
}

// evaluatePodRule dispatches to the appropriate rule evaluator by rule_id.
func evaluatePodRule(rule Rule, ismspItemID, ismspItemName string, req PodGraphRequest) PodRuleResult {
	base := PodRuleResult{
		RuleID:        rule.RuleID,
		Name:          rule.Name,
		ISMSPItem:     ismspItemID,
		ISMSPItemName: ismspItemName,
	}

	switch rule.RuleID {
	// 1.2.1 정보자산 식별
	case "R-1.2.1-POD-01":
		return evalNamespaceLabels(rule, req, base)
	case "R-1.2.1-POD-02":
		return evalAssetClassificationPolicy(rule, req, base)
	// 1.2.2 현황 및 흐름분석
	case "R-1.2.2-POD-01":
		return evalExternalDepLabel(rule, req, base)
	case "R-1.2.2-POD-02":
		return evalIngressFlowRegistered(rule, req, base)
	// 2.1.3 정보자산 관리
	case "R-2.1.3-POD-01":
		return evalWorkloadOwnerAnnotation(rule, req, base)
	case "R-2.1.3-POD-02":
		return evalSecurityClassLabel(rule, req, base)
	// 2.5.1 사용자 계정 관리
	case "R-2.5.1-POD-01":
		return evalDefaultServiceAccount(rule, req, base)
	case "R-2.5.1-POD-02":
		return evalSAOwnerLabel(rule, req, base)
	case "R-2.5.1-POD-03":
		return evalCrossTeamSASharing(rule, req, base)
	// 2.5.2 사용자 식별
	case "R-2.5.2-POD-01":
		return evalPredictableSAName(rule, req, base)
	case "R-2.5.2-POD-02":
		return evalGenericSANamePattern(rule, req, base)
	// 2.5.5 특수 계정 및 권한 관리
	case "R-2.5.5-POD-01":
		return evalServiceAccountPrivileges(rule, req, base)
	case "R-2.5.5-POD-02":
		return evalDangerousVerbCombos(rule, req, base)
	// 2.6.1 네트워크 접근
	case "R-2.6.1-POD-01":
		return evalHostNamespace(rule, req, base)
	case "R-2.6.1-POD-02":
		return evalNetworkPolicy(rule, req, base)
	case "R-2.6.1-POD-03":
		return evalCNIDaemonSet(rule, req, base)
	case "R-2.6.1-POD-04":
		return evalCrossNSTraffic(rule, req, base)
	// 2.6.3 응용프로그램 접근
	case "R-2.6.3-POD-01":
		return evalIngressAuth(rule, req, base)
	case "R-2.6.3-POD-02":
		return evalMTLS(rule, req, base)
	// 2.6.7 인터넷 접속 통제
	case "R-2.6.7-POD-01":
		return evalEgressPolicy(rule, req, base)
	// 2.7.1 암호정책 적용
	case "R-2.7.1-POD-01":
		return evalSecretEncryption(rule, req, base)
	case "R-2.7.1-POD-02":
		return evalConfigMapSecrets(rule, req, base)
	case "R-2.7.1-POD-03":
		return evalIngressTLS(rule, req, base)
	// 2.8.3 시험과 운영 환경 분리
	case "R-2.8.3-POD-01":
		return evalWorkloadEnvLabel(rule, req, base)
	case "R-2.8.3-POD-02":
		return evalNSEnvMixing(rule, req, base)
	case "R-2.8.3-POD-03":
		return evalCrossEnvSecretRef(rule, req, base)
	// 2.9.1 변경관리
	case "R-2.9.1-POD-01":
		return evalChangeCause(rule, req, base)
	case "R-2.9.1-POD-02":
		return evalRevisionHistoryLimit(rule, req, base)
	// 2.10.2 클라우드 보안
	case "R-2.10.2-POD-08":
		return evalNamespacePSA(rule, req, base)
	// 2.10.3 공개서버 보안
	case "R-2.10.3-POD-01":
		return evalLBSourceRange(rule, req, base)
	case "R-2.10.3-POD-02":
		return evalIngressWAF(rule, req, base)
	case "R-2.10.3-POD-03":
		return evalNodePortExposureLabel(rule, req, base)
	case "R-2.10.3-POD-04":
		return evalIngressRateLimit(rule, req, base)
	case "R-2.10.3-POD-05":
		return evalLBExposureLabel(rule, req, base)
	// 2.10.5 정보전송 보안
	case "R-2.10.5-POD-01":
		return evalExternalIngressTLS(rule, req, base)
	case "R-2.10.5-POD-03":
		return evalExternalNamePlaintext(rule, req, base)
	// 2.10.8 패치관리
	case "R-2.10.8-POD-01":
		return evalNodeKubeletVersion(rule, req, base)
	case "R-2.10.8-POD-02":
		return evalImageTagMutable(rule, req, base)
	case "R-2.10.8-POD-03":
		return evalImageDigest(rule, req, base)
	// 2.11.3 이상행위 분석 및 모니터링
	case "R-2.11.3-POD-01":
		return evalProdShellExec(rule, req, base)
	default:
		base.Verdict = "skip"
		base.SkipReason = fmt.Sprintf("알 수 없는 Pod 룰: %s", rule.RuleID)
		return base
	}
}

// ─────────────────────────────────────────────
// R-1.2.1-POD: Namespace 자산 분류 라벨 점검
// ─────────────────────────────────────────────

func evalNamespaceLabels(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	ns := req.RelatedResources.Namespace
	labels := jsonMap(ns, "metadata", "labels")
	nsName := jsonStr(ns, "metadata", "name")

	var violations []grc.Violation
	var matched []string

	for _, ind := range rule.ComplianceIndicators {
		if ind.Field == "" {
			continue
		}

		// Extract the label key from the field path: "namespace.metadata.labels.isms-p/scope" → "isms-p/scope"
		labelKey := extractLabelKey(ind.Field)
		if labelKey == "" {
			continue
		}

		val, exists := labels[labelKey]
		if !exists || val == nil {
			violations = append(violations, grc.Violation{
				Field:       ind.Field,
				Expected:    fmt.Sprintf("%s %v", ind.Op, ind.Value),
				Actual:      nil,
				Description: ind.Description,
				Severity:    "high",
				K8sSource: grc.K8sSource{
					Namespace:    nsName,
					ResourceKind: "Namespace",
					ResourceName: nsName,
				},
			})
			continue
		}

		valStr := fmt.Sprintf("%v", val)
		if !checkIndicatorMatch(valStr, ind) {
			violations = append(violations, grc.Violation{
				Field:       ind.Field,
				Expected:    fmt.Sprintf("%s %v", ind.Op, ind.Value),
				Actual:      valStr,
				Description: ind.Description,
				Severity:    "high",
				K8sSource: grc.K8sSource{
					Namespace:    nsName,
					ResourceKind: "Namespace",
					ResourceName: nsName,
				},
			})
		} else {
			matched = append(matched, fmt.Sprintf("%s=%s", labelKey, valStr))
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.5.5-POD: ServiceAccount 특수 권한 점검
// ─────────────────────────────────────────────

func evalServiceAccountPrivileges(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" {
		saName = "default"
	}
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	var violations []grc.Violation
	var matched []string

	hasClusterAdmin := false
	hasWildcard := false
	hasClusterWideSecrets := false

	// Check ClusterRoleBindings
	for _, crb := range req.RelatedResources.ClusterRoleBindings {
		subjects := jsonSlice(crb, "subjects")
		roleRef := jsonMap(crb, "roleRef")
		roleName := strVal(roleRef["name"])
		crbName := jsonStr(crb, "metadata", "name")

		if !subjectsMatchSA(subjects, saName, podNS) {
			continue
		}

		// Check cluster-admin binding
		if roleName == "cluster-admin" {
			hasClusterAdmin = true
			violations = append(violations, grc.Violation{
				Field:       "has_cluster_admin",
				Expected:    "== false",
				Actual:      true,
				Description: fmt.Sprintf("ServiceAccount '%s'가 cluster-admin에 바인딩됨 (바인딩: %s)", saName, crbName),
				Severity:    "critical",
				K8sSource: grc.K8sSource{
					Namespace:    podNS,
					ResourceKind: "ClusterRoleBinding",
					ResourceName: crbName,
				},
			})
		}

		// Check the referenced ClusterRole for wildcard/secrets permissions
		for _, cr := range req.RelatedResources.ClusterRoles {
			crName := jsonStr(cr, "metadata", "name")
			if crName != roleName {
				continue
			}
			rules := jsonSlice(cr, "rules")
			for _, r := range rules {
				rm := toMap(r)
				verbs := toStringSlice(rm["verbs"])
				resources := toStringSlice(rm["resources"])
				apiGroups := toStringSlice(rm["apiGroups"])

				if containsStr(verbs, "*") && containsStr(resources, "*") {
					hasWildcard = true
					violations = append(violations, grc.Violation{
						Field:       "has_wildcard_permission",
						Expected:    "== false",
						Actual:      true,
						Description: fmt.Sprintf("ClusterRole '%s'에 verbs:* + resources:* 와일드카드 권한 존재", crName),
						Severity:    "critical",
						K8sSource: grc.K8sSource{
							Namespace:    podNS,
							ResourceKind: "ClusterRole",
							ResourceName: crName,
						},
					})
				}

				if containsStr(resources, "secrets") && (containsStr(apiGroups, "") || containsStr(apiGroups, "*")) {
					secretVerbs := []string{"get", "list", "watch", "*"}
					for _, sv := range secretVerbs {
						if containsStr(verbs, sv) {
							hasClusterWideSecrets = true
							violations = append(violations, grc.Violation{
								Field:       "has_cluster_wide_secrets",
								Expected:    "== false",
								Actual:      true,
								Description: fmt.Sprintf("ClusterRole '%s'에 클러스터 전체 Secret 접근 권한 (verb: %s)", crName, sv),
								Severity:    "high",
								K8sSource: grc.K8sSource{
									Namespace:    podNS,
									ResourceKind: "ClusterRole",
									ResourceName: crName,
								},
							})
							break
						}
					}
				}
			}
		}
	}

	// Also check namespace-scoped RoleBindings referencing ClusterRoles or Roles
	for _, rb := range req.RelatedResources.RoleBindings {
		subjects := jsonSlice(rb, "subjects")
		roleRef := jsonMap(rb, "roleRef")
		roleName := strVal(roleRef["name"])
		roleKind := strVal(roleRef["kind"])

		if !subjectsMatchSA(subjects, saName, podNS) {
			continue
		}

		if roleKind == "ClusterRole" && roleName == "cluster-admin" {
			if !hasClusterAdmin {
				hasClusterAdmin = true
				rbName := jsonStr(rb, "metadata", "name")
				violations = append(violations, grc.Violation{
					Field:       "has_cluster_admin",
					Expected:    "== false",
					Actual:      true,
					Description: fmt.Sprintf("RoleBinding '%s'에서 cluster-admin ClusterRole 참조", rbName),
					Severity:    "critical",
					K8sSource: grc.K8sSource{
						Namespace:    podNS,
						ResourceKind: "RoleBinding",
						ResourceName: rbName,
					},
				})
			}
		}

		// Check namespace-scoped Roles
		if roleKind == "Role" {
			for _, role := range req.RelatedResources.Roles {
				if jsonStr(role, "metadata", "name") != roleName {
					continue
				}
				rules := jsonSlice(role, "rules")
				for _, r := range rules {
					rm := toMap(r)
					verbs := toStringSlice(rm["verbs"])
					resources := toStringSlice(rm["resources"])
					apiGroups := toStringSlice(rm["apiGroups"])

					if containsStr(verbs, "*") && containsStr(resources, "*") {
						hasWildcard = true
						violations = append(violations, grc.Violation{
							Field:       "has_wildcard_permission",
							Expected:    "== false",
							Actual:      true,
							Description: fmt.Sprintf("Role '%s'에 verbs:* + resources:* 와일드카드 권한 존재", roleName),
							Severity:    "critical",
							K8sSource: grc.K8sSource{
								Namespace:    podNS,
								ResourceKind: "Role",
								ResourceName: roleName,
							},
						})
					}

					if containsStr(resources, "secrets") && (containsStr(apiGroups, "") || containsStr(apiGroups, "*")) {
						secretVerbs := []string{"get", "list", "watch", "*"}
						for _, sv := range secretVerbs {
							if containsStr(verbs, sv) {
								hasClusterWideSecrets = true
								violations = append(violations, grc.Violation{
									Field:       "has_namespace_secrets",
									Expected:    "== false",
									Actual:      true,
									Description: fmt.Sprintf("Role '%s'에 Secret 접근 권한 (verb: %s)", roleName, sv),
									Severity:    "high",
									K8sSource: grc.K8sSource{
										Namespace:    podNS,
										ResourceKind: "Role",
										ResourceName: roleName,
									},
								})
								break
							}
						}
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		if !hasClusterAdmin {
			matched = append(matched, "cluster-admin 바인딩 없음")
		}
		if !hasWildcard {
			matched = append(matched, "와일드카드 권한 없음")
		}
		if !hasClusterWideSecrets {
			matched = append(matched, "클러스터 전체 Secret 접근 없음")
		}
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.6.1-POD-01: hostNetwork/hostPID/hostIPC 점검
// ─────────────────────────────────────────────

func evalHostNamespace(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	spec := jsonMap(req.Pod, "spec")
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// Check if pod is in a system namespace (exception)
	if rule.ExceptionCheck != nil {
		for _, sysNS := range rule.ExceptionCheck.SystemNamespaces {
			if podNS == sysNS {
				base.Verdict = "준수"
				base.MatchedIndicators = []string{fmt.Sprintf("시스템 네임스페이스 '%s' — 예외 적용", podNS)}
				return base
			}
		}
		// Check exception annotation
		if rule.ExceptionCheck.Annotation != "" {
			annotations := jsonMap(req.Pod, "metadata", "annotations")
			if _, ok := annotations[rule.ExceptionCheck.Annotation]; ok {
				base.Verdict = "준수"
				base.MatchedIndicators = []string{fmt.Sprintf("예외 사유 annotation '%s' 존재", rule.ExceptionCheck.Annotation)}
				return base
			}
		}
	}

	var violations []grc.Violation
	var matched []string

	hostFields := map[string]string{
		"hostNetwork": "hostNetwork=true — 노드 네트워크 스택 직접 공유, 네트워크 격리 무력화",
		"hostPID":     "hostPID=true — 노드 프로세스 네임스페이스 공유",
		"hostIPC":     "hostIPC=true — 노드 IPC 네임스페이스 공유",
	}

	for field, desc := range hostFields {
		val, _ := spec[field].(bool)
		if val {
			violations = append(violations, grc.Violation{
				Field:       fmt.Sprintf("pod.spec.%s", field),
				Expected:    "!= true",
				Actual:      true,
				Description: desc,
				Severity:    "critical",
				K8sSource: grc.K8sSource{
					Namespace:    podNS,
					ResourceKind: "Pod",
					ResourceName: podName,
				},
			})
		} else {
			matched = append(matched, fmt.Sprintf("%s 비활성", field))
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.6.1-POD-02: NetworkPolicy 적용 점검
// ─────────────────────────────────────────────

func evalNetworkPolicy(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	podLabels := jsonMap(req.Pod, "metadata", "labels")

	var violations []grc.Violation
	var matched []string

	hasDefaultDeny := false
	hasMatchingPolicy := false

	for _, np := range req.RelatedResources.NetworkPolicies {
		npName := jsonStr(np, "metadata", "name")
		npSpec := jsonMap(np, "spec")

		podSelector := jsonMap(np, "spec", "podSelector")
		matchLabels := jsonMap(podSelector, "matchLabels")
		policyTypes := toStringSlice(npSpec["policyTypes"])

		// Check for default-deny: empty podSelector + both Ingress/Egress in policyTypes
		selectorLabels := jsonMap(podSelector, "matchLabels")
		isEmptySelector := len(selectorLabels) == 0 && len(jsonSlice(podSelector, "matchExpressions")) == 0
		hasIngress := containsStr(policyTypes, "Ingress")
		hasEgress := containsStr(policyTypes, "Egress")

		if isEmptySelector && hasIngress && hasEgress {
			// Check if ingress/egress rules are empty (deny-all)
			ingressRules := jsonSlice(npSpec, "ingress")
			egressRules := jsonSlice(npSpec, "egress")
			if len(ingressRules) == 0 && len(egressRules) == 0 {
				hasDefaultDeny = true
				matched = append(matched, fmt.Sprintf("default-deny NetworkPolicy: %s", npName))
			}
		}

		// Check if policy matches this pod's labels
		if len(matchLabels) > 0 && labelsMatch(podLabels, matchLabels) {
			hasMatchingPolicy = true
			matched = append(matched, fmt.Sprintf("매칭 NetworkPolicy: %s", npName))
		}
		// Empty selector matches all pods
		if isEmptySelector {
			hasMatchingPolicy = true
		}
	}

	if !hasDefaultDeny {
		violations = append(violations, grc.Violation{
			Field:       "has_default_deny",
			Expected:    "== true",
			Actual:      false,
			Description: "default-deny NetworkPolicy 미존재 — 모든 Pod 간 무제한 통신 가능",
			Severity:    "high",
			K8sSource: grc.K8sSource{
				Namespace:    podNS,
				ResourceKind: "Namespace",
				ResourceName: podNS,
			},
		})
	}
	if !hasMatchingPolicy {
		violations = append(violations, grc.Violation{
			Field:       "has_matching_policy",
			Expected:    "== true",
			Actual:      false,
			Description: "Pod에 매칭되는 NetworkPolicy 없음 — 트래픽 통제 불가",
			Severity:    "high",
			K8sSource: grc.K8sSource{
				Namespace:    podNS,
				ResourceKind: "Pod",
				ResourceName: jsonStr(req.Pod, "metadata", "name"),
			},
		})
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.6.3-POD: Ingress 인증 적용 점검
// ─────────────────────────────────────────────

func evalIngressAuth(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	if len(req.RelatedResources.Ingresses) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Ingress 미사용 — 해당 없음"}
		return base
	}

	authAnnotationKeys := rule.AuthAnnotations
	if len(authAnnotationKeys) == 0 {
		authAnnotationKeys = []string{
			"nginx.ingress.kubernetes.io/auth-type",
			"nginx.ingress.kubernetes.io/auth-url",
			"alb.ingress.kubernetes.io/auth-type",
			"traefik.ingress.kubernetes.io/auth-type",
		}
	}

	var violations []grc.Violation
	var matched []string

	for _, ing := range req.RelatedResources.Ingresses {
		ingName := jsonStr(ing, "metadata", "name")
		annotations := jsonMap(ing, "metadata", "annotations")

		hasAuth := false
		for _, key := range authAnnotationKeys {
			if v, ok := annotations[key]; ok && v != nil && strVal(v) != "" {
				hasAuth = true
				matched = append(matched, fmt.Sprintf("Ingress '%s': %s=%v", ingName, key, v))
				break
			}
		}

		if !hasAuth {
			violations = append(violations, grc.Violation{
				Field:       "all_ingresses_have_auth",
				Expected:    "== true",
				Actual:      false,
				Description: fmt.Sprintf("Ingress '%s'에 인증 annotation 없음 — 비인가자 직접 접근 가능", ingName),
				Severity:    "high",
				K8sSource: grc.K8sSource{
					Namespace:    podNS,
					ResourceKind: "Ingress",
					ResourceName: ingName,
				},
			})
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// R-1.2.1-POD-02: 자산 분류 기준서 정책 ConfigMap 점검
// ─────────────────────────────────────────────

func evalAssetClassificationPolicy(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// Look for asset-classification-policy ConfigMap in the config_maps
	var policyCM map[string]any
	for _, cm := range req.RelatedResources.ConfigMaps {
		cmName := jsonStr(cm, "metadata", "name")
		if cmName == "asset-classification-policy" {
			policyCM = cm
			break
		}
	}

	if policyCM == nil {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "policy_configmap_exists",
			Expected:    "== true",
			Actual:      false,
			Description: "자산 분류 정책 ConfigMap 'asset-classification-policy' 부재",
			Severity:    "high",
			K8sSource: grc.K8sSource{
				Namespace:    podNS,
				ResourceKind: "Namespace",
				ResourceName: podNS,
			},
		}}
		return base
	}

	var violations []grc.Violation
	var matched []string

	// Check required data keys
	data := jsonMap(policyCM, "data")
	requiredKeys := []string{"classification-criteria", "criticality-criteria"}
	for _, key := range requiredKeys {
		if _, ok := data[key]; !ok || strVal(data[key]) == "" {
			violations = append(violations, grc.Violation{
				Field:       "has_all_required_keys",
				Expected:    "== true",
				Actual:      false,
				Description: fmt.Sprintf("분류 정책 ConfigMap에 필수 키 '%s' 누락", key),
				Severity:    "high",
				K8sSource: grc.K8sSource{
					Namespace:    jsonStr(policyCM, "metadata", "namespace"),
					ResourceKind: "ConfigMap",
					ResourceName: "asset-classification-policy",
				},
			})
		} else {
			matched = append(matched, fmt.Sprintf("키 '%s' 존재", key))
		}
	}

	// Check required annotations
	annotations := jsonMap(policyCM, "metadata", "annotations")
	requiredAnnotations := []string{"policy-version", "approved-by", "approved-at"}
	for _, ann := range requiredAnnotations {
		if _, ok := annotations[ann]; !ok || strVal(annotations[ann]) == "" {
			violations = append(violations, grc.Violation{
				Field:       "has_all_required_annotations",
				Expected:    "== true",
				Actual:      false,
				Description: fmt.Sprintf("정책 ConfigMap에 필수 annotation '%s' 누락", ann),
				Severity:    "medium",
				K8sSource: grc.K8sSource{
					Namespace:    jsonStr(policyCM, "metadata", "namespace"),
					ResourceKind: "ConfigMap",
					ResourceName: "asset-classification-policy",
				},
			})
		} else {
			matched = append(matched, fmt.Sprintf("annotation '%s'=%s", ann, strVal(annotations[ann])))
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		matched = append([]string{"정책 ConfigMap 존재"}, matched...)
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.5.5-POD-02: 위험 RBAC verb 조합 점검
// ─────────────────────────────────────────────

func evalDangerousVerbCombos(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" {
		saName = "default"
	}
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// Check exception
	if rule.ExceptionCheck != nil {
		for _, sysNS := range rule.ExceptionCheck.SystemNamespaces {
			if podNS == sysNS {
				base.Verdict = "준수"
				base.MatchedIndicators = []string{fmt.Sprintf("시스템 네임스페이스 '%s' — 예외 적용", podNS)}
				return base
			}
		}
	}

	type dangerousCombo struct {
		Name      string
		Verbs     []string
		Resources []string
		Risk      string
	}

	combos := []dangerousCombo{
		{Name: "pod_exec_attach", Verbs: []string{"create", "get"}, Resources: []string{"pods/exec", "pods/attach", "pods/portforward"}, Risk: "컨테이너 내부 임의 명령 실행"},
		{Name: "secret_write", Verbs: []string{"create", "update", "patch", "delete"}, Resources: []string{"secrets"}, Risk: "비밀정보 변조·삭제"},
		{Name: "rbac_escalate", Verbs: []string{"escalate"}, Resources: []string{"clusterroles", "roles"}, Risk: "RBAC 권한 자체 상승"},
		{Name: "rbac_bind", Verbs: []string{"bind"}, Resources: []string{"clusterroles", "roles"}, Risk: "임의 권한 바인딩"},
		{Name: "impersonate", Verbs: []string{"impersonate"}, Resources: []string{"users", "groups", "serviceaccounts"}, Risk: "다른 계정 가장"},
		{Name: "node_proxy", Verbs: []string{"get", "create"}, Resources: []string{"nodes/proxy"}, Risk: "kubelet API 직접 접근"},
		{Name: "sa_token_request", Verbs: []string{"create"}, Resources: []string{"serviceaccounts/token"}, Risk: "임의 SA 토큰 발급"},
	}

	var violations []grc.Violation

	// Collect all rules from ClusterRoles/Roles bound to this SA
	type rbacRule struct {
		Verbs     []string
		Resources []string
		RoleName  string
		RoleKind  string
	}
	var allRBACRules []rbacRule

	for _, crb := range req.RelatedResources.ClusterRoleBindings {
		subjects := jsonSlice(crb, "subjects")
		if !subjectsMatchSA(subjects, saName, podNS) {
			continue
		}
		roleRef := jsonMap(crb, "roleRef")
		roleName := strVal(roleRef["name"])
		for _, cr := range req.RelatedResources.ClusterRoles {
			if jsonStr(cr, "metadata", "name") != roleName {
				continue
			}
			for _, r := range jsonSlice(cr, "rules") {
				rm := toMap(r)
				allRBACRules = append(allRBACRules, rbacRule{
					Verbs:     toStringSlice(rm["verbs"]),
					Resources: toStringSlice(rm["resources"]),
					RoleName:  roleName,
					RoleKind:  "ClusterRole",
				})
			}
		}
	}

	for _, rb := range req.RelatedResources.RoleBindings {
		subjects := jsonSlice(rb, "subjects")
		if !subjectsMatchSA(subjects, saName, podNS) {
			continue
		}
		roleRef := jsonMap(rb, "roleRef")
		roleName := strVal(roleRef["name"])
		roleKind := strVal(roleRef["kind"])
		if roleKind == "ClusterRole" {
			for _, cr := range req.RelatedResources.ClusterRoles {
				if jsonStr(cr, "metadata", "name") != roleName {
					continue
				}
				for _, r := range jsonSlice(cr, "rules") {
					rm := toMap(r)
					allRBACRules = append(allRBACRules, rbacRule{
						Verbs:     toStringSlice(rm["verbs"]),
						Resources: toStringSlice(rm["resources"]),
						RoleName:  roleName,
						RoleKind:  roleKind,
					})
				}
			}
		} else if roleKind == "Role" {
			for _, role := range req.RelatedResources.Roles {
				if jsonStr(role, "metadata", "name") != roleName {
					continue
				}
				for _, r := range jsonSlice(role, "rules") {
					rm := toMap(r)
					allRBACRules = append(allRBACRules, rbacRule{
						Verbs:     toStringSlice(rm["verbs"]),
						Resources: toStringSlice(rm["resources"]),
						RoleName:  roleName,
						RoleKind:  "Role",
					})
				}
			}
		}
	}

	// Check each dangerous combo
	for _, combo := range combos {
		for _, rr := range allRBACRules {
			hasVerb := false
			hasResource := false
			for _, cv := range combo.Verbs {
				if containsStr(rr.Verbs, cv) || containsStr(rr.Verbs, "*") {
					hasVerb = true
					break
				}
			}
			for _, cr := range combo.Resources {
				if containsStr(rr.Resources, cr) || containsStr(rr.Resources, "*") {
					hasResource = true
					break
				}
			}
			if hasVerb && hasResource {
				violations = append(violations, grc.Violation{
					Field:       "has_dangerous_verb_combo",
					Expected:    "== false",
					Actual:      true,
					Description: fmt.Sprintf("%s '%s'에 위험 조합 '%s' — %s", rr.RoleKind, rr.RoleName, combo.Name, combo.Risk),
					Severity:    "critical",
					K8sSource: grc.K8sSource{
						Namespace:    podNS,
						ResourceKind: rr.RoleKind,
						ResourceName: rr.RoleName,
					},
				})
				break // one match per combo is enough
			}
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"위험 RBAC verb 조합 없음"}
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.6.3-POD-02: 내부 Service mTLS 강제 점검
// ─────────────────────────────────────────────

func evalMTLS(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	ns := req.RelatedResources.Namespace

	// Check istio-injection label on namespace
	nsLabels := jsonMap(ns, "metadata", "labels")
	istioInjection := strVal(nsLabels["istio-injection"])

	if istioInjection != "enabled" {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "istio_injection_enabled",
			Expected:    "== true",
			Actual:      false,
			Description: "namespace에 istio-injection=enabled 라벨 없음 — mTLS 강제 불가",
			Severity:    "high",
			K8sSource: grc.K8sSource{
				Namespace:    podNS,
				ResourceKind: "Namespace",
				ResourceName: podNS,
			},
		}}
		return base
	}

	// If istio is enabled, we consider it compliant
	// (full PeerAuthentication check would require custom Istio CRDs not in standard related_resources)
	base.Verdict = "준수"
	base.MatchedIndicators = []string{
		fmt.Sprintf("istio-injection=enabled (namespace: %s)", podNS),
		"Istio sidecar 주입 활성 — mTLS 적용 가능",
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.7.1-POD-01: Secret etcd 암호화 점검
// ─────────────────────────────────────────────

func evalSecretEncryption(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// Check if pod references any secrets
	secretNames := extractPodSecretRefs(req.Pod)
	if len(secretNames) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Pod에서 Secret 참조 없음 — 해당 없음"}
		return base
	}

	// Check EKS cluster encryptionConfig
	eksCluster := req.RelatedResources.EKSCluster
	if eksCluster == nil {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "eks_secrets_encrypted",
			Expected:    "== true",
			Actual:      false,
			Description: "EKS 클러스터 정보 미제공 — 암호화 설정 확인 불가",
			Severity:    "high",
			K8sSource: grc.K8sSource{
				Namespace:    podNS,
				ResourceKind: "Pod",
				ResourceName: jsonStr(req.Pod, "metadata", "name"),
			},
		}}
		return base
	}

	encryptionConfig := jsonSlice(eksCluster, "encryptionConfig")
	if encryptionConfig == nil {
		// Try nested under cluster key
		cluster := jsonMap(eksCluster, "cluster")
		if cluster != nil {
			encryptionConfig = jsonSlice(cluster, "encryptionConfig")
		}
	}

	secretsEncrypted := false
	var kmsKeyARN string
	for _, ec := range encryptionConfig {
		ecMap := toMap(ec)
		resources := toStringSlice(ecMap["resources"])
		if containsStr(resources, "secrets") {
			secretsEncrypted = true
			provider := toMap(ecMap["provider"])
			if provider != nil {
				kmsKeyARN = strVal(provider["keyArn"])
			}
			break
		}
	}

	if !secretsEncrypted {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "eks_secrets_encrypted",
			Expected:    "== true",
			Actual:      false,
			Description: fmt.Sprintf("etcd Secret 암호화 미설정 — Secret이 base64 인코딩으로만 저장 (참조 Secret: %s)", strings.Join(secretNames, ", ")),
			Severity:    "critical",
			K8sSource: grc.K8sSource{
				ClusterName:  req.ClusterName,
				ResourceKind: "EKSCluster",
				ResourceName: req.ClusterName,
			},
		}}
	} else {
		base.Verdict = "준수"
		indicators := []string{
			fmt.Sprintf("EKS secrets 암호화 설정됨 (KMS: %s)", kmsKeyARN),
			fmt.Sprintf("Pod 참조 Secret: %s", strings.Join(secretNames, ", ")),
		}
		base.MatchedIndicators = indicators
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.7.1-POD-02: ConfigMap 평문 비밀값 점검
// ─────────────────────────────────────────────

func evalConfigMapSecrets(rule Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// Get ConfigMap names referenced by the Pod
	cmNames := extractPodConfigMapRefs(req.Pod)
	if len(cmNames) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Pod에서 ConfigMap 참조 없음 — 해당 없음"}
		return base
	}

	// Compile secret patterns from rule
	patterns := rule.SecretPatterns
	if len(patterns) == 0 {
		patterns = defaultSecretPatterns()
	}

	compiledPatterns := make(map[string]*regexp.Regexp)
	for _, sp := range patterns {
		re, err := regexp.Compile(sp.Regex)
		if err != nil {
			log.Printf("[pod-graph] invalid secret pattern '%s': %v", sp.Name, err)
			continue
		}
		compiledPatterns[sp.Name] = re
	}

	var violations []grc.Violation
	var matched []string

	for _, cm := range req.RelatedResources.ConfigMaps {
		cmName := jsonStr(cm, "metadata", "name")

		// Only check ConfigMaps referenced by the pod
		if !containsStr(cmNames, cmName) {
			continue
		}

		data := jsonMap(cm, "data")
		for key, val := range data {
			valStr := strVal(val)
			for patternName, re := range compiledPatterns {
				if re.MatchString(valStr) {
					violations = append(violations, grc.Violation{
						Field:       "configmap_has_secrets",
						Expected:    "== false",
						Actual:      true,
						Description: fmt.Sprintf("ConfigMap '%s' 키 '%s'에 %s 패턴 매칭 — Secret 오브젝트로 이관 필요", cmName, key, patternName),
						Severity:    "high",
						K8sSource: grc.K8sSource{
							Namespace:    podNS,
							ResourceKind: "ConfigMap",
							ResourceName: cmName,
						},
					})
					break // one match per key is enough
				}
			}
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		matched = append(matched, fmt.Sprintf("점검 ConfigMap: %s — 평문 비밀값 없음", strings.Join(cmNames, ", ")))
		base.MatchedIndicators = matched
	}
	return base
}

// ─────────────────────────────────────────────
// JSON Navigation Helpers
// ─────────────────────────────────────────────

// jsonMap safely extracts a nested map by key path.
func jsonMap(obj map[string]any, keys ...string) map[string]any {
	current := obj
	for _, k := range keys {
		if current == nil {
			return nil
		}
		next, ok := current[k].(map[string]any)
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

// jsonStr safely extracts a string value by key path.
func jsonStr(obj map[string]any, keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	if len(keys) == 1 {
		return strVal(obj[keys[0]])
	}
	parent := jsonMap(obj, keys[:len(keys)-1]...)
	if parent == nil {
		return ""
	}
	return strVal(parent[keys[len(keys)-1]])
}

// jsonSlice safely extracts a slice by key path.
func jsonSlice(obj map[string]any, keys ...string) []any {
	if len(keys) == 0 {
		return nil
	}
	var target any
	if len(keys) == 1 {
		target = obj[keys[0]]
	} else {
		parent := jsonMap(obj, keys[:len(keys)-1]...)
		if parent == nil {
			return nil
		}
		target = parent[keys[len(keys)-1]]
	}
	if s, ok := target.([]any); ok {
		return s
	}
	return nil
}

// strVal converts any value to string.
func strVal(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// toStringSlice converts any to []string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			result = append(result, strVal(item))
		}
		return result
	}
	return nil
}

// containsStr checks if a string slice contains a value.
func containsStr(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────
// Pod Metadata Extraction
// ─────────────────────────────────────────────

func extractPodMeta(pod map[string]any) (name, namespace string) {
	name = jsonStr(pod, "metadata", "name")
	namespace = jsonStr(pod, "metadata", "namespace")
	return
}

// extractLabelKey extracts the label key from a dotted field path.
// e.g. "namespace.metadata.labels.isms-p/scope" → "isms-p/scope"
func extractLabelKey(field string) string {
	const prefix = "namespace.metadata.labels."
	if strings.HasPrefix(field, prefix) {
		return field[len(prefix):]
	}
	return ""
}

// checkIndicatorMatch checks if a value satisfies a compliance indicator.
func checkIndicatorMatch(val string, ind Indicator) bool {
	switch ind.Op {
	case "in":
		if allowed, ok := ind.Value.([]any); ok {
			for _, a := range allowed {
				if strings.EqualFold(val, strVal(a)) {
					return true
				}
			}
		}
		return false
	case "!=":
		return val != strVal(ind.Value) && val != ""
	case "==":
		return strings.EqualFold(val, strVal(ind.Value))
	default:
		return val != ""
	}
}

// subjectsMatchSA checks if any RBAC subject matches the given ServiceAccount.
func subjectsMatchSA(subjects []any, saName, namespace string) bool {
	for _, s := range subjects {
		subj := toMap(s)
		if subj == nil {
			continue
		}
		if strVal(subj["kind"]) == "ServiceAccount" &&
			strVal(subj["name"]) == saName &&
			(strVal(subj["namespace"]) == "" || strVal(subj["namespace"]) == namespace) {
			return true
		}
	}
	return false
}

// labelsMatch checks if pod labels contain all selector labels.
func labelsMatch(podLabels, selectorLabels map[string]any) bool {
	for k, v := range selectorLabels {
		podVal, ok := podLabels[k]
		if !ok || strVal(podVal) != strVal(v) {
			return false
		}
	}
	return true
}

// extractPodSecretRefs extracts all Secret names referenced by a Pod.
func extractPodSecretRefs(pod map[string]any) []string {
	seen := map[string]bool{}
	var names []string

	spec := jsonMap(pod, "spec")
	if spec == nil {
		return nil
	}

	// volumes[].secret.secretName
	volumes := jsonSlice(spec, "volumes")
	for _, v := range volumes {
		vm := toMap(v)
		if vm == nil {
			continue
		}
		secret := toMap(vm["secret"])
		if secret != nil {
			name := strVal(secret["secretName"])
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	// containers[].envFrom[].secretRef.name + containers[].env[].valueFrom.secretKeyRef.name
	containers := jsonSlice(spec, "containers")
	for _, c := range containers {
		cm := toMap(c)
		if cm == nil {
			continue
		}
		envFrom := toSlice(cm["envFrom"])
		for _, ef := range envFrom {
			efm := toMap(ef)
			if efm == nil {
				continue
			}
			secretRef := toMap(efm["secretRef"])
			if secretRef != nil {
				name := strVal(secretRef["name"])
				if name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
		envVars := toSlice(cm["env"])
		for _, ev := range envVars {
			evm := toMap(ev)
			if evm == nil {
				continue
			}
			valueFrom := toMap(evm["valueFrom"])
			if valueFrom == nil {
				continue
			}
			secretKeyRef := toMap(valueFrom["secretKeyRef"])
			if secretKeyRef != nil {
				name := strVal(secretKeyRef["name"])
				if name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}

	return names
}

// extractPodConfigMapRefs extracts all ConfigMap names referenced by a Pod.
func extractPodConfigMapRefs(pod map[string]any) []string {
	seen := map[string]bool{}
	var names []string

	spec := jsonMap(pod, "spec")
	if spec == nil {
		return nil
	}

	// volumes[].configMap.name
	volumes := jsonSlice(spec, "volumes")
	for _, v := range volumes {
		vm := toMap(v)
		if vm == nil {
			continue
		}
		configMap := toMap(vm["configMap"])
		if configMap != nil {
			name := strVal(configMap["name"])
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	// containers[].envFrom[].configMapRef.name
	containers := jsonSlice(spec, "containers")
	for _, c := range containers {
		cm := toMap(c)
		if cm == nil {
			continue
		}
		envFrom := toSlice(cm["envFrom"])
		for _, ef := range envFrom {
			efm := toMap(ef)
			if efm == nil {
				continue
			}
			configMapRef := toMap(efm["configMapRef"])
			if configMapRef != nil {
				name := strVal(configMapRef["name"])
				if name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}

	return names
}

func defaultSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{Name: "password", Regex: `(?i)(password|passwd|pwd)\s*[:=]\s*["']?[\w@!#$%^&*-]{6,}`},
		{Name: "aws_access_key", Regex: `AKIA[0-9A-Z]{16}`},
		{Name: "private_key", Regex: `-----BEGIN [A-Z ]*PRIVATE KEY-----`},
		{Name: "secret_token", Regex: `(?i)(secret|token|api[_-]?key)\s*[:=]\s*["']?[\w\-.]{16,}`},
		{Name: "jwt", Regex: `eyJ[\w-]+\.[\w-]+\.[\w-]+`},
	}
}

// ─────────────────────────────────────────────
// Textualization: K8s resource → human-readable text (for embedding)
// ─────────────────────────────────────────────

// textualizePodResource converts a K8s resource JSON into human-readable text for BGE-M3 embedding.
func textualizePodResource(resourceType string, data map[string]any) string {
	if data == nil {
		return ""
	}
	switch resourceType {
	case "pod":
		return textualizePod(data)
	case "namespace":
		return textualizeNamespace(data)
	case "networkpolicy":
		return textualizeNetworkPolicy(data)
	case "ingress":
		return textualizeIngress(data)
	case "configmap":
		return textualizeConfigMap(data)
	case "clusterrolebinding":
		return textualizeClusterRoleBinding(data)
	case "clusterrole":
		return textualizeClusterRole(data)
	case "rolebinding":
		return textualizeRoleBinding(data)
	case "ekscluster":
		return textualizeEKSCluster(data)
	default:
		b, _ := json.Marshal(data)
		if len(b) > 4000 {
			b = b[:4000]
		}
		return fmt.Sprintf("Kubernetes %s resource:\n%s", resourceType, string(b))
	}
}

func textualizePod(pod map[string]any) string {
	name := jsonStr(pod, "metadata", "name")
	ns := jsonStr(pod, "metadata", "namespace")
	sa := jsonStr(pod, "spec", "serviceAccountName")
	if sa == "" {
		sa = "default"
	}
	spec := jsonMap(pod, "spec")

	var parts []string
	parts = append(parts, fmt.Sprintf("Kubernetes Pod: %s", name))
	parts = append(parts, fmt.Sprintf("Namespace: %s", ns))
	parts = append(parts, fmt.Sprintf("ServiceAccount: %s", sa))

	if spec != nil {
		hostNet, _ := spec["hostNetwork"].(bool)
		hostPID, _ := spec["hostPID"].(bool)
		hostIPC, _ := spec["hostIPC"].(bool)
		parts = append(parts, fmt.Sprintf("hostNetwork: %v, hostPID: %v, hostIPC: %v", hostNet, hostPID, hostIPC))
	}

	// Volumes
	volumes := jsonSlice(pod, "spec", "volumes")
	if len(volumes) > 0 {
		var volNames []string
		for _, v := range volumes {
			vm := toMap(v)
			if vm == nil {
				continue
			}
			vn := strVal(vm["name"])
			if toMap(vm["secret"]) != nil {
				vn += "(secret:" + strVal(toMap(vm["secret"])["secretName"]) + ")"
			} else if toMap(vm["configMap"]) != nil {
				vn += "(configMap:" + strVal(toMap(vm["configMap"])["name"]) + ")"
			}
			volNames = append(volNames, vn)
		}
		parts = append(parts, fmt.Sprintf("Volumes: [%s]", strings.Join(volNames, ", ")))
	}

	// Containers
	containers := jsonSlice(pod, "spec", "containers")
	if len(containers) > 0 {
		var cNames []string
		for _, c := range containers {
			cm := toMap(c)
			if cm != nil {
				cNames = append(cNames, strVal(cm["name"]))
			}
		}
		parts = append(parts, fmt.Sprintf("Containers: [%s]", strings.Join(cNames, ", ")))
	}

	// Labels
	labels := jsonMap(pod, "metadata", "labels")
	if len(labels) > 0 {
		var lblParts []string
		for k, v := range labels {
			lblParts = append(lblParts, fmt.Sprintf("%s=%v", k, v))
		}
		parts = append(parts, fmt.Sprintf("Labels: %s", strings.Join(lblParts, ", ")))
	}

	return strings.Join(parts, "\n")
}

func textualizeNamespace(ns map[string]any) string {
	name := jsonStr(ns, "metadata", "name")
	labels := jsonMap(ns, "metadata", "labels")

	var parts []string
	parts = append(parts, fmt.Sprintf("Kubernetes Namespace: %s", name))
	if len(labels) > 0 {
		for k, v := range labels {
			parts = append(parts, fmt.Sprintf("  Label %s = %v", k, v))
		}
	}
	return strings.Join(parts, "\n")
}

func textualizeNetworkPolicy(np map[string]any) string {
	name := jsonStr(np, "metadata", "name")
	ns := jsonStr(np, "metadata", "namespace")
	policyTypes := toStringSlice(jsonMap(np, "spec")["policyTypes"])
	podSelector := jsonMap(np, "spec", "podSelector")
	matchLabels := jsonMap(podSelector, "matchLabels")

	var parts []string
	parts = append(parts, fmt.Sprintf("NetworkPolicy: %s (namespace: %s)", name, ns))
	parts = append(parts, fmt.Sprintf("PolicyTypes: %s", strings.Join(policyTypes, ", ")))

	if len(matchLabels) == 0 {
		parts = append(parts, "PodSelector: {} (모든 Pod에 적용)")
	} else {
		var sel []string
		for k, v := range matchLabels {
			sel = append(sel, fmt.Sprintf("%s=%v", k, v))
		}
		parts = append(parts, fmt.Sprintf("PodSelector: %s", strings.Join(sel, ", ")))
	}

	ingressRules := jsonSlice(np, "spec", "ingress")
	egressRules := jsonSlice(np, "spec", "egress")
	if len(ingressRules) == 0 && len(egressRules) == 0 {
		parts = append(parts, "Ingress/Egress 룰 없음 (deny-all)")
	} else {
		parts = append(parts, fmt.Sprintf("Ingress 룰 %d개, Egress 룰 %d개", len(ingressRules), len(egressRules)))
	}
	return strings.Join(parts, "\n")
}

func textualizeIngress(ing map[string]any) string {
	name := jsonStr(ing, "metadata", "name")
	annotations := jsonMap(ing, "metadata", "annotations")
	rules := jsonSlice(ing, "spec", "rules")

	var parts []string
	parts = append(parts, fmt.Sprintf("Ingress: %s", name))

	// Auth annotations
	authKeys := []string{
		"nginx.ingress.kubernetes.io/auth-type",
		"nginx.ingress.kubernetes.io/auth-url",
		"alb.ingress.kubernetes.io/auth-type",
		"traefik.ingress.kubernetes.io/auth-type",
	}
	for _, key := range authKeys {
		if v, ok := annotations[key]; ok && v != nil {
			parts = append(parts, fmt.Sprintf("  인증 annotation: %s = %v", key, v))
		}
	}

	// Hosts
	for _, r := range rules {
		rm := toMap(r)
		if rm != nil {
			host := strVal(rm["host"])
			if host != "" {
				parts = append(parts, fmt.Sprintf("  Host: %s", host))
			}
		}
	}
	return strings.Join(parts, "\n")
}

func textualizeConfigMap(cm map[string]any) string {
	name := jsonStr(cm, "metadata", "name")
	ns := jsonStr(cm, "metadata", "namespace")
	data := jsonMap(cm, "data")

	var parts []string
	parts = append(parts, fmt.Sprintf("ConfigMap: %s (namespace: %s)", name, ns))
	parts = append(parts, fmt.Sprintf("키 수: %d", len(data)))

	for k, v := range data {
		valStr := strVal(v)
		if len(valStr) > 200 {
			valStr = valStr[:200] + "..."
		}
		parts = append(parts, fmt.Sprintf("  %s = %s", k, valStr))
	}
	return strings.Join(parts, "\n")
}

func textualizeClusterRoleBinding(crb map[string]any) string {
	name := jsonStr(crb, "metadata", "name")
	roleRef := jsonMap(crb, "roleRef")
	subjects := jsonSlice(crb, "subjects")

	var parts []string
	parts = append(parts, fmt.Sprintf("ClusterRoleBinding: %s", name))
	if roleRef != nil {
		parts = append(parts, fmt.Sprintf("  RoleRef: %s/%s", strVal(roleRef["kind"]), strVal(roleRef["name"])))
	}
	for _, s := range subjects {
		sm := toMap(s)
		if sm != nil {
			parts = append(parts, fmt.Sprintf("  Subject: %s/%s (ns: %s)", strVal(sm["kind"]), strVal(sm["name"]), strVal(sm["namespace"])))
		}
	}
	return strings.Join(parts, "\n")
}

func textualizeClusterRole(cr map[string]any) string {
	name := jsonStr(cr, "metadata", "name")
	rules := jsonSlice(cr, "rules")

	var parts []string
	parts = append(parts, fmt.Sprintf("ClusterRole: %s", name))
	for i, r := range rules {
		rm := toMap(r)
		if rm == nil {
			continue
		}
		verbs := toStringSlice(rm["verbs"])
		resources := toStringSlice(rm["resources"])
		apiGroups := toStringSlice(rm["apiGroups"])
		parts = append(parts, fmt.Sprintf("  Rule[%d]: apiGroups=[%s] resources=[%s] verbs=[%s]",
			i, strings.Join(apiGroups, ","), strings.Join(resources, ","), strings.Join(verbs, ",")))
	}
	return strings.Join(parts, "\n")
}

func textualizeRoleBinding(rb map[string]any) string {
	name := jsonStr(rb, "metadata", "name")
	ns := jsonStr(rb, "metadata", "namespace")
	roleRef := jsonMap(rb, "roleRef")
	subjects := jsonSlice(rb, "subjects")

	var parts []string
	parts = append(parts, fmt.Sprintf("RoleBinding: %s (namespace: %s)", name, ns))
	if roleRef != nil {
		parts = append(parts, fmt.Sprintf("  RoleRef: %s/%s", strVal(roleRef["kind"]), strVal(roleRef["name"])))
	}
	for _, s := range subjects {
		sm := toMap(s)
		if sm != nil {
			parts = append(parts, fmt.Sprintf("  Subject: %s/%s", strVal(sm["kind"]), strVal(sm["name"])))
		}
	}
	return strings.Join(parts, "\n")
}

func textualizeEKSCluster(eks map[string]any) string {
	// May be wrapped in {"cluster": {...}} from AWS describe-cluster
	cluster := jsonMap(eks, "cluster")
	if cluster == nil {
		cluster = eks
	}
	name := strVal(cluster["name"])
	encConfig := jsonSlice(cluster, "encryptionConfig")

	var parts []string
	parts = append(parts, fmt.Sprintf("EKS Cluster: %s", name))

	if len(encConfig) > 0 {
		for _, ec := range encConfig {
			ecm := toMap(ec)
			if ecm == nil {
				continue
			}
			resources := toStringSlice(ecm["resources"])
			provider := toMap(ecm["provider"])
			keyArn := ""
			if provider != nil {
				keyArn = strVal(provider["keyArn"])
			}
			parts = append(parts, fmt.Sprintf("  EncryptionConfig: resources=%s, KMS keyArn=%s",
				strings.Join(resources, ","), keyArn))
		}
	} else {
		parts = append(parts, "  EncryptionConfig: 없음")
	}
	return strings.Join(parts, "\n")
}

// ─────────────────────────────────────────────
// PodRuleResult → grc.RuleResult conversion
// ─────────────────────────────────────────────

// convertPodRuleResult converts a PodRuleResult to a grc.RuleResult for unified storage.
func convertPodRuleResult(pr PodRuleResult, checkID string, evidenceFiles []string) grc.RuleResult {
	return grc.RuleResult{
		CheckID:           checkID,
		RuleID:            pr.RuleID,
		CheckCategory:     "pod_graph",
		EvidenceType:      pr.Name,
		System:            "AWS EKS",
		Verdict:           pr.Verdict,
		EvidenceFiles:     evidenceFiles,
		MatchedIndicators: pr.MatchedIndicators,
		Violations:        pr.Violations,
	}
}

// buildSyntheticEvidenceFiles creates synthetic evidence file entries from a PodGraphRequest.
// Returns a list of (filename, resourceType, data) tuples ready for storage.
type syntheticEvidence struct {
	Filename     string
	ResourceType string
	Data         map[string]any
	K8sSource    grc.K8sSource
}

func buildSyntheticEvidenceList(req PodGraphRequest) []syntheticEvidence {
	podName, podNS := extractPodMeta(req.Pod)
	var list []syntheticEvidence

	// Pod
	list = append(list, syntheticEvidence{
		Filename:     fmt.Sprintf("pod_%s.json", podName),
		ResourceType: "pod",
		Data:         req.Pod,
		K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
	})

	// Namespace
	if req.RelatedResources.Namespace != nil {
		nsName := jsonStr(req.RelatedResources.Namespace, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("namespace_%s.json", nsName),
			ResourceType: "namespace",
			Data:         req.RelatedResources.Namespace,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: nsName, ResourceKind: "Namespace", ResourceName: nsName},
		})
	}

	// NetworkPolicies
	for _, np := range req.RelatedResources.NetworkPolicies {
		npName := jsonStr(np, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("networkpolicy_%s.json", npName),
			ResourceType: "networkpolicy",
			Data:         np,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: podNS, ResourceKind: "NetworkPolicy", ResourceName: npName},
		})
	}

	// Ingresses
	for _, ing := range req.RelatedResources.Ingresses {
		ingName := jsonStr(ing, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("ingress_%s.json", ingName),
			ResourceType: "ingress",
			Data:         ing,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: podNS, ResourceKind: "Ingress", ResourceName: ingName},
		})
	}

	// ConfigMaps
	for _, cm := range req.RelatedResources.ConfigMaps {
		cmName := jsonStr(cm, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("configmap_%s.json", cmName),
			ResourceType: "configmap",
			Data:         cm,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: podNS, ResourceKind: "ConfigMap", ResourceName: cmName},
		})
	}

	// ClusterRoleBindings
	for _, crb := range req.RelatedResources.ClusterRoleBindings {
		crbName := jsonStr(crb, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("clusterrolebinding_%s.json", crbName),
			ResourceType: "clusterrolebinding",
			Data:         crb,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, ResourceKind: "ClusterRoleBinding", ResourceName: crbName},
		})
	}

	// RoleBindings
	for _, rb := range req.RelatedResources.RoleBindings {
		rbName := jsonStr(rb, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("rolebinding_%s.json", rbName),
			ResourceType: "rolebinding",
			Data:         rb,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: podNS, ResourceKind: "RoleBinding", ResourceName: rbName},
		})
	}

	// ClusterRoles
	for _, cr := range req.RelatedResources.ClusterRoles {
		crName := jsonStr(cr, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("clusterrole_%s.json", crName),
			ResourceType: "clusterrole",
			Data:         cr,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, ResourceKind: "ClusterRole", ResourceName: crName},
		})
	}

	// Roles
	for _, role := range req.RelatedResources.Roles {
		roleName := jsonStr(role, "metadata", "name")
		roleNS := jsonStr(role, "metadata", "namespace")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("role_%s_%s.json", roleNS, roleName),
			ResourceType: "role",
			Data:         role,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: roleNS, ResourceKind: "Role", ResourceName: roleName},
		})
	}

	// ServiceAccounts
	for _, sa := range req.RelatedResources.ServiceAccounts {
		saName := jsonStr(sa, "metadata", "name")
		saNS := jsonStr(sa, "metadata", "namespace")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("serviceaccount_%s_%s.json", saNS, saName),
			ResourceType: "serviceaccount",
			Data:         sa,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: saNS, ResourceKind: "ServiceAccount", ResourceName: saName},
		})
	}

	// Workloads
	for _, wl := range req.RelatedResources.Workloads {
		wlName := jsonStr(wl, "metadata", "name")
		wlNS := jsonStr(wl, "metadata", "namespace")
		kind := jsonStr(wl, "kind")
		if kind == "" {
			kind = "Workload"
		}
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("workload_%s_%s.json", wlNS, wlName),
			ResourceType: "workload",
			Data:         wl,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: wlNS, ResourceKind: kind, ResourceName: wlName},
		})
	}

	// Secrets (metadata only for evidence)
	for _, sec := range req.RelatedResources.Secrets {
		secName := jsonStr(sec, "metadata", "name")
		secNS := jsonStr(sec, "metadata", "namespace")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("secret_%s_%s.json", secNS, secName),
			ResourceType: "secret",
			Data:         sec,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, Namespace: secNS, ResourceKind: "Secret", ResourceName: secName},
		})
	}

	// Nodes
	for _, node := range req.RelatedResources.Nodes {
		nodeName := jsonStr(node, "metadata", "name")
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("node_%s.json", nodeName),
			ResourceType: "node",
			Data:         node,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, ResourceKind: "Node", ResourceName: nodeName},
		})
	}

	// EKS Cluster
	if req.RelatedResources.EKSCluster != nil {
		list = append(list, syntheticEvidence{
			Filename:     fmt.Sprintf("ekscluster_%s.json", req.ClusterName),
			ResourceType: "ekscluster",
			Data:         req.RelatedResources.EKSCluster,
			K8sSource:    grc.K8sSource{ClusterName: req.ClusterName, ResourceKind: "EKSCluster", ResourceName: req.ClusterName},
		})
	}

	return list
}
