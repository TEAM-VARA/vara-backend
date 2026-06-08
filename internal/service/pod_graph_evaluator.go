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
	NotApplicable       int                       `json:"not_applicable,omitempty"` // 해당없음 (vacuous pass)
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
	NotApplicable  int              `json:"not_applicable,omitempty"` // 해당없음 (vacuous pass)
	Summary        *PodGraphSummary `json:"summary,omitempty"`
	RuleResults    []PodRuleResult  `json:"rule_results"`
}

// PodRuleResult holds the verdict for a single Pod-graph rule.
type PodRuleResult struct {
	RuleID            string              `json:"rule_id"`
	Name              string              `json:"name"`
	ISMSPItem         string              `json:"isms_p_item"`
	ISMSPItemName     string              `json:"isms_p_item_name"`
	Severity          string              `json:"severity,omitempty"`
	Verdict           string              `json:"verdict"` // MET | NOT_MET | NO_DATA | skip
	Violations        []grc.Violation     `json:"violations,omitempty"`
	MatchedIndicators []string            `json:"matched_indicators,omitempty"`
	FailMessage       string              `json:"fail_message,omitempty"`
	SkipReason        string              `json:"skip_reason,omitempty"`
	Remediation       string              `json:"remediation,omitempty"`
	Reason            string              `json:"reason,omitempty"`
	MissingInputs     json.RawMessage     `json:"missing_inputs,omitempty"`
	Layer             string              `json:"layer,omitempty"`
}

// ─────────────────────────────────────────────
// Main Evaluator
// ─────────────────────────────────────────────

// EvaluatePodGraph evaluates all Pod-graph rulesets against the provided K8s resources.
func (s *GRCService) EvaluatePodGraph(ctx context.Context, req PodGraphRequest) (*PodGraphResult, error) {
	rulesets := s.rulesetStore.LoadAll()
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

	var unimplemented []string
	for _, rs := range rulesets {
		for _, rule := range rs.Rules {
			// Skip non-k8s rules (e.g. text_extraction, guideline_rag) in pod graph evaluation
			if rule.JudgmentSource != "" && rule.JudgmentSource != "k8s_native" && rule.JudgmentSource != "k8s_api" {
				continue
			}
			// Skip F- (finding) rules — handled by finding_evaluator
			if strings.HasPrefix(rule.RuleID, "F-") {
				continue
			}
			// Skip GL- (guideline) rules — handled by text_extraction evaluator
			if strings.Contains(rule.RuleID, "-GL") {
				continue
			}
			// Skip manual rules — handled by EvaluateManualRules (승격/리포트/deferred 포함).
			// 룰셋 JSON이 judgment_source=k8s_api로 선언했어도 수동 룰이면 Pod 평가 대상 아님
			// (기존엔 여기서 "알 수 없는 Pod 룰" skip이 Pod 수만큼 중복 생성됨).
			if rule.IsManual() {
				continue
			}
			// Skip rules with no pod-level evaluator implementation.
			// 카탈로그에는 있으나 엔진 미구현인 룰(예: R-2.5.4-03~15)을 사전 제외해
			// "알 수 없는 Pod 룰" skip 노이즈(13룰×Pod 수 = 182건)를 제거한다.
			if !podRuleImplemented(rule.RuleID) {
				unimplemented = append(unimplemented, rule.RuleID)
				continue
			}
			rr := evaluatePodRule(rule, rs.Item.ID, rs.Item.Name, req)
			// 미측정(NO_DATA/skip/판정불가) 결과에 K8s 외부 확인처 가이드 부착
			rr = attachOffClusterGuidance(rr, rule, rs.Item.ID)
			result.RuleResults = append(result.RuleResults, rr)
			log.Printf("[pod-graph] rule=%s verdict=%s", rule.RuleID, rr.Verdict)
		}
	}
	if len(unimplemented) > 0 {
		log.Printf("[pod-graph] excluded %d unimplemented pod rules: %s",
			len(unimplemented), strings.Join(unimplemented, ","))
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
		case "준수", grc.VerdictMET:
			result.Passed++
			summary.Pass++
			summary.BySeverity[sev].Pass++
		case grc.VerdictNA, "해당없음":
			// 점검 대상 부재 — 준수/미준수 어디에도 포함하지 않음
			result.NotApplicable++
			summary.NotApplicable++
		case "skip", grc.VerdictSKIPPED:
			result.Skipped++
			summary.Skip++
		case grc.VerdictNO_DATA, grc.VerdictINDETERMINATE, grc.VerdictNEEDS_REVIEW:
			// 판단 불가(데이터 부재/확인불가/검토필요) — 확정 미준수가 아니므로
			// pod 단위 OverallVerdict를 미준수로 만들지 않고 skip 버킷으로 집계한다.
			// (항목 단위 집계에서는 NEEDS_REVIEW를 '검토필요'로 별도 분리한다.)
			result.Skipped++
			summary.Skip++
		default: // 미준수, NOT_MET
			result.Failed++
			summary.Fail++
			summary.BySeverity[sev].Fail++
			result.OverallVerdict = "미준수"
		}
	}
	result.Summary = summary

	// Persist to DB (NA는 skipped 버킷에 합산 — 스키마 호환: total = passed+failed+skipped)
	id, err := s.repo.SavePodGraphEvaluation(ctx,
		req.CompanyID, req.ClusterName, podName, namespace,
		result.OverallVerdict, result.TotalRules, result.Passed, result.Failed, result.Skipped+result.NotApplicable,
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

// ruleFailInfo holds the fail message and remediation for a rule.
type ruleFailInfo struct {
	failMessage string
	remediation string
}

// podRuleFailInfo maps canonical rule IDs (without -POD-) to their fail/remediation messages.
//
// NOTE: 자기증명(self-attestation) 라벨/annotation 룰 11개 제거됨 —
// R-1.2.1-01/02, R-1.2.2-01/02, R-2.1.3-01/02, R-2.5.1-02, R-2.8.3-01,
// R-2.9.1-01, R-2.10.3-03/05. 라벨 부착 여부는 클러스터 동작·보안과 무관하고
// ISMS-P 증적 효력도 없음. 해당 항목(1.2.1, 1.2.2, 2.1.3)은 GL룰(정책 문서 점검)과
// REPORT형 인벤토리로 커버한다.
var podRuleFailInfo = map[string]ruleFailInfo{
	// 2.5.1 사용자 계정 관리
	"R-2.5.1-01": {"Pod이 default ServiceAccount를 사용 중", "Pod에 전용 ServiceAccount를 생성하여 할당하고 automountServiceAccountToken을 필요한 경우에만 활성화하세요"},
	"R-2.5.1-03": {"여러 팀/네임스페이스에서 동일 ServiceAccount를 공유하여 사용 중", "팀별·용도별 전용 ServiceAccount를 분리하여 사용하세요"},
	// 2.5.2 사용자 식별
	"R-2.5.2-01": {"예측 가능한 ServiceAccount 이름 사용(default, admin 등)", "ServiceAccount 이름에 팀/용도를 포함하여 고유하게 지정하세요"},
	"R-2.5.2-02": {"일반적(generic) ServiceAccount 이름 패턴 사용", "admin, default, system 등 일반적인 이름 대신 app-name-sa 형식의 용도별 고유 이름을 사용하세요"},
	// 2.5.5 특수 계정 및 권한 관리
	"R-2.5.5-01": {"ServiceAccount에 과도한 권한(cluster-admin, wildcard 등) 부여됨", "최소 권한 원칙에 따라 RBAC Role/ClusterRole을 세분화하고 불필요한 권한을 제거하세요"},
	"R-2.5.5-02": {"위험한 verb 조합(escalate, bind, impersonate 등) 감지", "escalate, bind, impersonate 등 위험 verb를 제거하고 필요 최소한의 권한만 부여하세요"},
	// 2.6.1 네트워크 접근
	"R-2.6.1-01": {"Pod이 hostNetwork, hostPID 또는 hostIPC를 사용 중", "Pod spec에서 hostNetwork, hostPID, hostIPC를 false로 설정하세요"},
	"R-2.6.1-02": {"Pod에 적용되는 NetworkPolicy 없음", "Pod에 적용되는 Ingress/Egress NetworkPolicy를 생성하여 네트워크 접근을 통제하세요"},
	"R-2.6.1-03": {"클러스터에 CNI 플러그인 DaemonSet 미감지", "클러스터에 CNI 플러그인(Calico, Cilium 등)이 설치되어 NetworkPolicy가 적용 가능한지 확인하세요"},
	"R-2.6.1-04": {"다른 네임스페이스로의 네트워크 트래픽 감지", "NetworkPolicy로 교차 네임스페이스 트래픽을 제한하여 네트워크 분리를 강화하세요"},
	// 2.6.3 응용프로그램 접근
	"R-2.6.3-01": {"Ingress에 인증 설정(auth-url, auth-type 등) 부재", "Ingress에 인증 annotation(nginx.ingress.kubernetes.io/auth-url 등)을 추가하세요"},
	"R-2.6.3-02": {"서비스 간 mTLS 미적용", "서비스 메시(Istio, Linkerd 등)를 통해 mTLS를 활성화하거나 sidecar injection을 설정하세요"},
	// 2.6.7 인터넷 접속 통제
	"R-2.6.7-01": {"Pod에 Egress NetworkPolicy 미적용", "Pod에 Egress NetworkPolicy를 적용하여 외부 인터넷 접속을 통제하세요"},
	// 2.7.1 암호정책 적용
	"R-2.7.1-01": {"Secret이 etcd에 암호화되지 않은 상태로 저장될 수 있음", "etcd 저장 시 Secret 암호화(EncryptionConfiguration)를 활성화하세요"},
	"R-2.7.1-02": {"ConfigMap에 비밀번호, API 키 등 민감 정보 포함 의심", "ConfigMap에서 민감 정보를 제거하고 Secret 리소스로 이동하세요"},
	"R-2.7.1-03": {"Ingress에 TLS 설정 미적용", "Ingress에 TLS 인증서를 설정하여 HTTPS 통신을 보장하세요"},
	"R-2.7.1-04": {"Ingress에 TLS 설정 미적용", "Ingress에 TLS 인증서를 설정하여 HTTPS 통신을 보장하세요"},
	// 2.8.3 시험과 운영 환경 분리
	"R-2.8.3-02": {"하나의 네임스페이스에 서로 다른 환경의 워크로드가 혼합 배치됨", "production과 staging/development 워크로드를 별도 네임스페이스로 분리하세요"},
	"R-2.8.3-03": {"다른 환경의 Secret을 교차 참조하고 있음", "환경별 Secret을 분리하여 교차 환경 참조를 제거하세요"},
	// 2.9.1 변경관리
	"R-2.9.1-02": {"revisionHistoryLimit이 미설정이거나 부적절한 값", "Deployment의 revisionHistoryLimit을 적정 수준(5~10)으로 설정하여 롤백 이력을 관리하세요"},
	// 2.10.2 클라우드 보안
	"R-2.10.2-08": {"Namespace에 Pod Security Admission(PSA) 라벨 미설정", "Namespace에 pod-security.kubernetes.io/enforce 라벨을 추가하여 Pod 보안 기준을 적용하세요"},
	// 2.10.3 공개서버 보안
	"R-2.10.3-01": {"LoadBalancer Service에 sourceRanges 미설정으로 모든 IP에서 접근 가능", "LoadBalancer Service에 spec.loadBalancerSourceRanges를 설정하여 접근 IP를 제한하세요"},
	"R-2.10.3-02": {"Ingress에 WAF(Web Application Firewall) annotation 미설정", "Ingress에 WAF annotation을 추가하여 웹 공격으로부터 보호하세요"},
	"R-2.10.3-04": {"Ingress에 Rate Limit 설정 미적용", "Ingress에 rate-limiting annotation을 추가하여 요청 빈도를 제한하세요"},
	// 2.10.5 정보전송 보안
	"R-2.10.5-01": {"외부 노출 Ingress에 TLS 미설정으로 평문 통신 위험", "외부 노출 Ingress에 TLS 인증서를 설정하여 전송 구간 암호화를 보장하세요"},
	"R-2.10.5-03": {"ExternalName Service가 평문(HTTP) 프로토콜 사용", "ExternalName Service의 대상을 HTTPS 엔드포인트로 변경하세요"},
	// 2.10.8 패치관리
	"R-2.10.8-01": {"Node의 kubelet 버전이 오래되어 보안 패치 적용이 필요함", "Node의 kubelet을 최신 안정 버전으로 업데이트하세요"},
	"R-2.10.8-02": {"컨테이너 이미지에 변경 가능한 태그(latest 등) 사용", "이미지 태그에 고정 버전(예: v1.2.3)을 사용하여 배포 일관성을 보장하세요"},
	"R-2.10.8-03": {"컨테이너 이미지에 digest(@sha256:...) 미지정", "이미지 참조에 @sha256:... digest를 포함하여 이미지 무결성을 보장하세요"},
	// 2.11.3 이상행위 분석 및 모니터링
	"R-2.11.3-01": {"프로덕션 환경 Pod에서 대화형 셸(exec) 실행 감지", "프로덕션 Pod에서 대화형 셸 실행을 제한하는 OPA/Kyverno 정책을 적용하세요"},
}

// dataSourceAvailability tracks which K8s field prefixes have backing data in the DB.
// Fields whose resource tables lack the required columns (e.g. labels/annotations) are marked false.
var dataSourceAvailability = map[string]bool{
	"pod.metadata.labels":                  true,
	"pod.metadata.annotations":             true,
	"pod.spec":                             true,
	"namespace.metadata.labels":            false, // cluster_namespaces has no labels column
	"namespace.metadata.annotations":       false,
	"externalname_service.metadata.labels": false, // cluster_services has no labels column
	"service.metadata.labels":              false,
	"service.metadata.annotations":         false,
	"ingress.metadata.labels":              false, // cluster_ingresses has no labels column
	"ingress.metadata.annotations":         false,
	"workload.metadata.labels":             false,
	"workload.metadata.annotations":        false,
	"node.metadata.labels":                 true, // cluster_nodes has labels
	// network_policy, role, configmap, etc.: assumed available
}

// indicatorFieldPrefix extracts the resource-level prefix from a field path.
// e.g. "namespace.metadata.labels.isms-p/scope" → "namespace.metadata.labels"
func indicatorFieldPrefix(field string) string {
	parts := strings.Split(field, ".")
	// For labels/annotations paths like "namespace.metadata.labels.X", return first 3 segments.
	if len(parts) >= 3 {
		prefix := strings.Join(parts[:3], ".")
		if strings.HasSuffix(prefix, ".labels") || strings.HasSuffix(prefix, ".annotations") {
			return prefix
		}
	}
	// For spec paths like "pod.spec.hostNetwork", return first 2 segments.
	if len(parts) >= 2 {
		return strings.Join(parts[:2], ".")
	}
	return field
}

// checkIndicatorDataAvailability checks if the rule's indicators reference data sources that exist in DB.
// Returns the count of evaluable and noData indicators.
func checkIndicatorDataAvailability(indicators []Indicator) (evaluable int, noData int, missingFields []string) {
	for _, ind := range indicators {
		if ind.Field == "" {
			continue
		}
		prefix := indicatorFieldPrefix(ind.Field)
		available, known := dataSourceAvailability[prefix]
		if known && !available {
			noData++
			missingFields = append(missingFields, ind.Field)
		} else {
			evaluable++
		}
	}
	return
}

// implementedPodRules is the set of canonical rule IDs (without -POD-) that have
// a pod-level evaluator in evaluatePodRule's dispatch switch. Rules declared in
// ruleset JSON with judgment_source=k8s_api but missing here are excluded from
// pod evaluation up-front (P1-8: "알 수 없는 Pod 룰" skip 노이즈 제거).
var implementedPodRules = map[string]bool{
	"R-2.5.1-01": true, "R-2.5.1-03": true,
	"R-2.5.2-01": true, "R-2.5.2-02": true,
	"R-2.5.5-01": true, "R-2.5.5-02": true,
	"R-2.6.1-01": true, "R-2.6.1-02": true, "R-2.6.1-03": true, "R-2.6.1-04": true,
	"R-2.6.3-01": true, "R-2.6.3-02": true,
	"R-2.6.7-01": true,
	"R-2.7.1-01": true, "R-2.7.1-02": true, "R-2.7.1-03": true, "R-2.7.1-04": true,
	"R-2.8.3-02": true, "R-2.8.3-03": true,
	"R-2.9.1-02": true,
	"R-2.10.2-08": true,
	"R-2.10.3-01": true, "R-2.10.3-02": true, "R-2.10.3-04": true,
	"R-2.10.5-01": true, "R-2.10.5-03": true,
	"R-2.10.8-01": true, "R-2.10.8-02": true, "R-2.10.8-03": true,
	"R-2.11.3-01": true,
}

// podRuleImplemented reports whether a pod-level evaluator exists for the rule.
func podRuleImplemented(ruleID string) bool {
	return implementedPodRules[strings.Replace(ruleID, "-POD-", "-", 1)]
}

// ─────────────────────────────────────────────
// 미측정 룰 외부 확인처 가이드
// ─────────────────────────────────────────────

// ruleOffClusterHints maps canonical rule IDs to "K8s 밖에서 어디를 확인해야
// 하는지" guidance, used when the rule result is 미측정 (NO_DATA/skip/판정불가).
// 룰셋 JSON의 offcluster_satisfaction_conditions가 있으면 그것이 우선한다.
var ruleOffClusterHints = map[string]string{
	"R-1.2.1-01":  "자산관리대장/CMDB의 K8s 자산 등재·분류등급·중요도 산정 현황",
	"R-1.2.2-01":  "정보서비스 흐름도·외부 연계 시스템 목록(외부 의존성 등록 여부)",
	"R-1.2.2-02":  "정보서비스 흐름도(Ingress 진입 경로 반영 여부)",
	"R-2.1.3-02":  "CMDB의 자산별 보안등급 분류",
	"R-2.5.1-02":  "사내 CMDB/IAM의 SA-소유팀 매핑, SA 발급 신청·승인 기록",
	"R-2.8.3-01":  "별도 클러스터/VPC 환경 분리 현황, namespace 네이밍 컨벤션, 배포 파이프라인의 환경 정의",
	"R-2.8.3-03":  "별도 클러스터/VPC 환경 분리 현황, namespace 네이밍 컨벤션(환경 식별 수단)",
	"R-2.9.1-01":  "ITSM 변경관리 신청·승인 결재 기록, 배포 파이프라인 이력",
	"R-2.10.2-08": "EKS 콘솔의 namespace Pod Security 설정, CSPM/클라우드 보안 점검 보고서",
	"R-2.10.8-01": "EKS 콘솔/노드그룹의 kubelet 버전·지원 종료일(EOL) 현황",
	"R-2.11.3-01": "K8s Audit Log(CloudWatch Logs), Falco/Tetragon 등 런타임 탐지 도구, SIEM 보관 로그",
}

// itemOffClusterHints is the per-item fallback when no rule-level hint exists.
var itemOffClusterHints = map[string]string{
	"1.2.1":  "자산관리대장/CMDB",
	"1.2.2":  "정보서비스·개인정보 흐름도, 외부 위탁 계약 목록",
	"2.1.3":  "CMDB·ITSM(자산/변경 결재 기록)",
	"2.5.1":  "계정 관리 대장, 계정 정기 점검 기록",
	"2.5.2":  "IAM/계정 발급 기록",
	"2.5.4":  "OS·AD·IAM 비밀번호 정책 설정 증적, 비밀번호 관리 지침",
	"2.5.5":  "특수 계정 목록, 권한 부여 승인 결재 기록",
	"2.6.1":  "VPC 서브넷/Security Group 설계서, 네트워크 구성도",
	"2.6.3":  "API 게이트웨이/IdP의 인증 설정, 응용 접근통제 정책",
	"2.6.7":  "NAT Gateway 화이트리스트, 프록시·외부 방화벽 정책",
	"2.7.1":  "EKS Secret 암호화(KMS) 설정, ALB TLS 정책, 암호정책 문서",
	"2.8.3":  "클러스터/VPC 환경 분리 현황, 배포 파이프라인 환경 정의",
	"2.9.1":  "ITSM 변경 신청·승인 기록",
	"2.10.2": "클라우드 보안 설정 점검(CSPM), EKS 콘솔",
	"2.10.3": "VPC SG/WAF 콘솔, 공개 자산(LB/도메인) 목록",
	"2.10.5": "ALB/CloudFront TLS 설정, 조직 간 전송 협약",
	"2.10.8": "패치 적용 기록, 이미지 스캔(Trivy 등) 리포트",
	"2.11.3": "Audit Log/SIEM, 이상행위 탐지 도구 운영 기록",
}

// offClusterCheckHint resolves the external check guidance for a rule:
// ruleset JSON metadata first, then rule-level map, then item-level fallback.
func offClusterCheckHint(rule Rule, itemID string) string {
	if rule.ManualCheckOutput != nil && len(rule.ManualCheckOutput.OffclusterSatisfactionConditions) > 0 {
		return strings.Join(rule.ManualCheckOutput.OffclusterSatisfactionConditions, " / ")
	}
	if rule.ManualMeta != nil && len(rule.ManualMeta.OffclusterSatisfactionConditions) > 0 {
		return strings.Join(rule.ManualMeta.OffclusterSatisfactionConditions, " / ")
	}
	canonical := strings.Replace(rule.RuleID, "-POD-", "-", 1)
	if h, ok := ruleOffClusterHints[canonical]; ok {
		return h
	}
	if h, ok := itemOffClusterHints[itemID]; ok {
		return h
	}
	return "외부 통제(클라우드 콘솔·CMDB·ITSM·정책 문서)에서 충족 여부 확인"
}

// attachOffClusterGuidance appends "K8s 측정 범위 외 — 확인처" guidance to every
// 미측정 result (NO_DATA / SKIPPED / INDETERMINATE). 미측정 ≠ 미준수: K8s 밖에서
// 충족 중일 수 있으므로, 어디를 확인해야 하는지를 결과 텍스트에 직접 싣는다.
// N_A(대상 리소스 부재)와 REPORT(정보 제공)는 미측정이 아니므로 제외한다.
func attachOffClusterGuidance(rr PodRuleResult, rule Rule, itemID string) PodRuleResult {
	switch grc.NormalizeVerdict(rr.Verdict) {
	case grc.VerdictNO_DATA, grc.VerdictSKIPPED, grc.VerdictINDETERMINATE:
		// fall through to attach
	default:
		return rr
	}
	hint := fmt.Sprintf("K8s 측정 범위 외 — 확인처: %s", offClusterCheckHint(rule, itemID))
	switch {
	case rr.SkipReason != "":
		rr.SkipReason += " ▸ " + hint
	case rr.Reason != "":
		rr.Reason += " ▸ " + hint
	default:
		// 빈 메시지로 렌더링되던 미측정 결과도 확인처가 본문이 된다.
		rr.Reason = hint
	}
	return rr
}

// allIndicatorsNA reports whether every matched indicator marks the rule as
// "해당 없음" (점검 대상 리소스 부재 — vacuous pass).
func allIndicatorsNA(indicators []string) bool {
	if len(indicators) == 0 {
		return false
	}
	for _, mi := range indicators {
		if !strings.Contains(mi, "해당 없음") {
			return false
		}
	}
	return true
}

// evaluatePodRule dispatches to the appropriate rule evaluator by rule_id.
func evaluatePodRule(rule Rule, ismspItemID, ismspItemName string, req PodGraphRequest) PodRuleResult {
	base := PodRuleResult{
		RuleID:        rule.RuleID,
		Name:          rule.Name,
		ISMSPItem:     ismspItemID,
		ISMSPItemName: ismspItemName,
	}

	// Pre-check: if all indicators reference unavailable data sources, return NO_DATA.
	if len(rule.ComplianceIndicators) > 0 {
		evaluable, noData, missingFields := checkIndicatorDataAvailability(rule.ComplianceIndicators)
		if noData > 0 && evaluable == 0 {
			base.Verdict = grc.VerdictNO_DATA
			base.Reason = fmt.Sprintf("수집 범위 외 — 자동점검 불가 (해당 필드 미수집, %d개 인디케이터)", noData)
			base.Layer = grc.LayerR
			if mj, err := json.Marshal(missingFields); err == nil {
				base.MissingInputs = mj
			}
			return base
		}
	}

	var result PodRuleResult
	switch rule.RuleID {
	// 2.5.1 사용자 계정 관리
	case "R-2.5.1-POD-01", "R-2.5.1-01":
		result = evalDefaultServiceAccount(rule, req, base)
	case "R-2.5.1-POD-03", "R-2.5.1-03":
		result = evalCrossTeamSASharing(rule, req, base)
	// 2.5.2 사용자 식별
	case "R-2.5.2-POD-01", "R-2.5.2-01":
		result = evalPredictableSAName(rule, req, base)
	case "R-2.5.2-POD-02", "R-2.5.2-02":
		result = evalGenericSANamePattern(rule, req, base)
	// 2.5.5 특수 계정 및 권한 관리
	case "R-2.5.5-POD-01", "R-2.5.5-01":
		result = evalServiceAccountPrivileges(rule, req, base)
	case "R-2.5.5-POD-02", "R-2.5.5-02":
		result = evalDangerousVerbCombos(rule, req, base)
	// 2.6.1 네트워크 접근
	case "R-2.6.1-POD-01", "R-2.6.1-01":
		result = evalHostNamespace(rule, req, base)
	case "R-2.6.1-POD-02", "R-2.6.1-02":
		result = evalNetworkPolicy(rule, req, base)
	case "R-2.6.1-POD-03", "R-2.6.1-03":
		result = evalCNIDaemonSet(rule, req, base)
	case "R-2.6.1-POD-04", "R-2.6.1-04":
		result = evalCrossNSTraffic(rule, req, base)
	// 2.6.3 응용프로그램 접근
	case "R-2.6.3-POD-01", "R-2.6.3-01":
		result = evalIngressAuth(rule, req, base)
	case "R-2.6.3-POD-02", "R-2.6.3-02":
		result = evalMTLS(rule, req, base)
	// 2.6.7 인터넷 접속 통제
	case "R-2.6.7-POD-01", "R-2.6.7-01":
		result = evalEgressPolicy(rule, req, base)
	// 2.7.1 암호정책 적용
	case "R-2.7.1-POD-01", "R-2.7.1-01":
		result = evalSecretEncryption(rule, req, base)
	case "R-2.7.1-POD-02", "R-2.7.1-02":
		result = evalConfigMapSecrets(rule, req, base)
	case "R-2.7.1-POD-03", "R-2.7.1-03":
		result = evalIngressTLS(rule, req, base)
	case "R-2.7.1-04":
		result = evalIngressTLS(rule, req, base) // TLS 관련 추가 룰
	// 2.8.3 시험과 운영 환경 분리
	case "R-2.8.3-POD-02", "R-2.8.3-02":
		result = evalNSEnvMixing(rule, req, base)
	case "R-2.8.3-POD-03", "R-2.8.3-03":
		result = evalCrossEnvSecretRef(rule, req, base)
	// 2.9.1 변경관리
	case "R-2.9.1-POD-02", "R-2.9.1-02":
		result = evalRevisionHistoryLimit(rule, req, base)
	// 2.10.2 클라우드 보안
	case "R-2.10.2-POD-08", "R-2.10.2-08":
		result = evalNamespacePSA(rule, req, base)
	// 2.10.3 공개서버 보안
	case "R-2.10.3-POD-01", "R-2.10.3-01":
		result = evalLBSourceRange(rule, req, base)
	case "R-2.10.3-POD-02", "R-2.10.3-02":
		result = evalIngressWAF(rule, req, base)
	case "R-2.10.3-POD-04", "R-2.10.3-04":
		result = evalIngressRateLimit(rule, req, base)
	// 2.10.5 정보전송 보안
	case "R-2.10.5-POD-01", "R-2.10.5-01":
		result = evalExternalIngressTLS(rule, req, base)
	case "R-2.10.5-POD-03", "R-2.10.5-03":
		result = evalExternalNamePlaintext(rule, req, base)
	// 2.10.8 패치관리
	case "R-2.10.8-POD-01", "R-2.10.8-01":
		result = evalNodeKubeletVersion(rule, req, base)
	case "R-2.10.8-POD-02", "R-2.10.8-02":
		result = evalImageTagMutable(rule, req, base)
	case "R-2.10.8-POD-03", "R-2.10.8-03":
		result = evalImageDigest(rule, req, base)
	// 2.11.3 이상행위 분석 및 모니터링
	case "R-2.11.3-POD-01", "R-2.11.3-01":
		result = evalProdShellExec(rule, req, base)
	default:
		base.Verdict = "skip"
		base.SkipReason = fmt.Sprintf("알 수 없는 Pod 룰: %s", rule.RuleID)
		return base
	}

	// Set layer for all R-rule results
	if result.Layer == "" {
		result.Layer = grc.LayerR
	}

	// 점검 대상 리소스 부재("해당 없음")로 통과한 vacuous pass는 자동 N_A로 두지 않는다.
	// K8s에서 대상을 못 찾았다는 것이 곧 "해당없음(적용 제외)"을 의미하지 않으며
	// (암호화는 서비스메시/DB, 외부전송은 클러스터 외부, 공개노출은 다른 경로로 가능),
	// 인증범위 문서로 대상 부재가 확인되기 전까지는 적용성·대체통제 재확인 대상이다.
	// → 준수로 부풀리지도, 해당없음으로 단정하지도 않고 NEEDS_REVIEW(검토필요)로 둔다.
	if result.Verdict == "준수" && allIndicatorsNA(result.MatchedIndicators) {
		result.Verdict = grc.VerdictNEEDS_REVIEW
		var naDetails []string
		for _, mi := range result.MatchedIndicators {
			naDetails = append(naDetails, mi)
		}
		detail := strings.Join(naDetails, "; ")
		result.Reason = fmt.Sprintf("점검 대상 리소스 부재: %s. 인증범위 문서에서 대상 부재가 확인되면 N/A 처리 가능합니다.", detail)
	}

	// 미준수 판정 시 FailMessage/Remediation 자동 부여
	if result.Verdict == "미준수" {
		nid := strings.Replace(rule.RuleID, "-POD-", "-", 1)
		if info, ok := podRuleFailInfo[nid]; ok {
			result.FailMessage = info.failMessage
			result.Remediation = info.remediation
		}
	}
	return result
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

	// 시스템 네임스페이스 예외: kube-system 등 시스템 컴포넌트에 sidecar injection을
	// 요구하는 것은 비현실적 (Istio 공식 문서도 kube-system 제외 권장).
	if isSystemNamespace(podNS) {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("시스템 네임스페이스 '%s' — mTLS 예외 적용", podNS)}
		return base
	}

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
