package service

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// systemNamespaces are platform-managed namespaces exempt from org-policy rules
// (계정/자산/메시 관련 룰의 시스템 컴포넌트 예외 — 2.5.1과 동일 정책).
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

func isSystemNamespace(ns string) bool { return systemNamespaces[ns] }

// podHasController reports whether the Pod shows evidence of being managed by a
// workload controller (Deployment/ReplicaSet/DaemonSet 등). Used to distinguish
// "워크로드가 정말 없음"(N/A) from "워크로드 수집 누락"(NO_DATA).
func podHasController(pod map[string]any) bool {
	if len(jsonSlice(pod, "metadata", "ownerReferences")) > 0 {
		return true
	}
	labels := jsonMap(pod, "metadata", "labels")
	if _, ok := labels["pod-template-hash"]; ok {
		return true // ReplicaSet/Deployment 산하
	}
	if _, ok := labels["controller-revision-hash"]; ok {
		return true // DaemonSet/StatefulSet 산하
	}
	return false
}

// workloadDataMissing reports that the snapshot has no workload rows even though
// the Pod is clearly controller-managed — i.e. collection gap, not real absence.
func workloadDataMissing(req PodGraphRequest) bool {
	return len(req.RelatedResources.Workloads) == 0 && podHasController(req.Pod)
}

// noDataWorkloadResult builds a NO_DATA verdict for workload-collection gaps.
func noDataWorkloadResult(base PodRuleResult) PodRuleResult {
	base.Verdict = grc.VerdictNO_DATA
	base.Reason = "워크로드(Deployment/DaemonSet 등) 데이터 미수집 — Pod에 컨트롤러 흔적(ownerReferences/pod-template-hash)이 있으나 workload 스냅샷이 비어 있음. 수집기 확인 필요"
	return base
}

// NOTE: 자기증명(self-attestation) 라벨/annotation 평가기 제거됨
// (R-1.2.2-01/02, R-2.1.3-01/02 등 — pod_graph_evaluator.go의 podRuleFailInfo NOTE 참조).
// 1.2.1/1.2.2/2.1.3 항목은 GL룰(정책 문서 점검) + REPORT형 인벤토리로 커버한다.

// ─────────────────────────────────────────────
// 2.5.1 사용자 계정 관리
// ─────────────────────────────────────────────

// R-2.5.1-POD-01: default ServiceAccount 사용
func evalDefaultServiceAccount(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")

	// system namespace exception
	systemNS := map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true}
	if systemNS[podNS] {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("시스템 네임스페이스 '%s' — 예외 적용", podNS)}
		return base
	}

	if saName == "" || saName == "default" {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "spec.serviceAccountName",
			Expected:    "not in [\"\", \"default\"]",
			Actual:      saName,
			Description: fmt.Sprintf("Pod '%s/%s'이 default SA를 사용 (공용계정 사용)", podNS, podName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("SA=%s (default 아님)", saName)}
	}
	return base
}

// R-2.5.1-POD-03: 팀 간 ServiceAccount 공유
func evalCrossTeamSASharing(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" || saName == "default" {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"default SA — 공유 점검 불필요"}
		return base
	}

	// Count unique teams using this SA from workloads
	teams := map[string]bool{}
	for _, wl := range req.RelatedResources.Workloads {
		wlSA := jsonStr(wl, "spec", "template", "spec", "serviceAccountName")
		if wlSA != saName {
			continue
		}
		team := strVal(jsonMap(wl, "metadata", "labels")["team"])
		if team == "" {
			team = strVal(jsonMap(wl, "spec", "template", "metadata", "labels")["team"])
		}
		if team != "" {
			teams[team] = true
		}
	}

	if len(teams) >= 2 {
		teamList := make([]string, 0, len(teams))
		for t := range teams {
			teamList = append(teamList, t)
		}
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "cross_team_sa_sharing",
			Expected:    "team count <= 1",
			Actual:      len(teams),
			Description: fmt.Sprintf("SA '%s'을 여러 팀이 공유 (teams: %s)", saName, strings.Join(teamList, ", ")),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: jsonStr(req.Pod, "metadata", "namespace"), ResourceKind: "ServiceAccount", ResourceName: saName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("SA '%s' 단일 팀 사용", saName)}
	}
	return base
}

// ─────────────────────────────────────────────
// 2.5.2 사용자 식별
// ─────────────────────────────────────────────

// predictableSARegex: 추측 가능한 SA 이름 deny list.
// 'default' 포함 — fail message("예측 가능한 ServiceAccount 이름 사용(default, admin 등)")와
// 2.5.1-01(default SA 미준수) 판정과 일관되도록 수정 (기존엔 default가 통과하는 버그).
var predictableSARegex = regexp.MustCompile(`^(default|admin|root|test|temp|guest|system|operator)(-.*)?$`)

// genericSARegex: 일반(generic) 명명 패턴 — user1, sa2 같은 번호형 + 무의미한 단독 이름.
var genericSARegex = regexp.MustCompile(`^(user|account|sa|app|service|svc)[0-9]*$`)

// R-2.5.2-POD-01: 추측 가능한 SA 이름
func evalPredictableSAName(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" {
		saName = "default"
	}
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// 시스템 네임스페이스 예외 (2.5.1과 동일 정책)
	if isSystemNamespace(podNS) {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("시스템 네임스페이스 '%s' — 예외 적용", podNS)}
		return base
	}

	if predictableSARegex.MatchString(saName) {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "spec.serviceAccountName",
			Expected:    "not match predictable pattern",
			Actual:      saName,
			Description: fmt.Sprintf("SA 이름 '%s'이 추측 가능한 패턴", saName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "ServiceAccount", ResourceName: saName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("SA '%s' — 추측 불가 이름", saName)}
	}
	return base
}

// R-2.5.2-POD-02: 일반 명명 패턴
func evalGenericSANamePattern(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" {
		saName = "default"
	}
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// 시스템 네임스페이스 예외 (2.5.1과 동일 정책)
	if isSystemNamespace(podNS) {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("시스템 네임스페이스 '%s' — 예외 적용", podNS)}
		return base
	}

	// default SA는 R-2.5.2-01(추측 가능 이름)에서 이미 미준수 처리 — 중복 위반 방지
	if saName == "default" {
		base.Verdict = "skip"
		base.SkipReason = "default SA — R-2.5.2-01에서 판정 (중복 방지)"
		return base
	}

	if genericSARegex.MatchString(saName) {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "spec.serviceAccountName",
			Expected:    "not match generic pattern",
			Actual:      saName,
			Description: fmt.Sprintf("SA 이름 '%s'이 일반 명명 패턴", saName),
			Severity:    "medium",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "ServiceAccount", ResourceName: saName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("SA '%s' — 고유 명명", saName)}
	}
	return base
}

// ─────────────────────────────────────────────
// 2.6.1 네트워크 접근 (추가 룰)
// ─────────────────────────────────────────────

// R-2.6.1-POD-03: CNI 정책 강제 DaemonSet 미배포
func evalCNIDaemonSet(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"

	// 수집 누락 가드: workload 데이터가 아예 없으면 "CNI 미감지"는 측정 결과가 아니라
	// 데이터 부재다 (이번 클러스터의 aws-node DaemonSet이 미수집으로 미준수 처리된 사례).
	if len(req.RelatedResources.Workloads) == 0 {
		return noDataWorkloadResult(base)
	}

	cniNames := []string{"calico-node", "cilium", "calico-kube-controllers", "weave-net", "aws-node"}

	for _, wl := range req.RelatedResources.Workloads {
		wlNS := jsonStr(wl, "metadata", "namespace")
		wlName := jsonStr(wl, "metadata", "name")
		kind := jsonStr(wl, "kind")
		if wlNS != "kube-system" {
			continue
		}
		if kind != "" && kind != "DaemonSet" {
			continue
		}
		for _, cni := range cniNames {
			if wlName == cni || strings.HasPrefix(wlName, cni+"-") {
				base.Verdict = "준수"
				base.MatchedIndicators = []string{fmt.Sprintf("CNI DaemonSet '%s' 존재 (kube-system)", wlName)}
				return base
			}
		}
	}

	base.Verdict = "미준수"
	base.Violations = []grc.Violation{{
		Field:       "has_policy_capable_cni",
		Expected:    "== true",
		Actual:      false,
		Description: "NetworkPolicy 강제 CNI(Calico/Cilium) DaemonSet 미배포",
		Severity:    "high",
		K8sSource:   grc.K8sSource{Namespace: "kube-system", ResourceKind: "DaemonSet"},
	}}
	return base
}

// R-2.6.1-POD-04: cross-namespace 통신 통제 부재
func evalCrossNSTraffic(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	podName := jsonStr(req.Pod, "metadata", "name")

	// Check if any NetworkPolicy restricts egress cross-namespace
	hasEgressPolicy := false
	for _, np := range req.RelatedResources.NetworkPolicies {
		npSpec := jsonMap(np, "spec")
		policyTypes := toStringSlice(npSpec["policyTypes"])
		if !containsStr(policyTypes, "Egress") {
			continue
		}
		// Check if podSelector matches this pod
		podSelector := jsonMap(np, "spec", "podSelector")
		selectorLabels := jsonMap(podSelector, "matchLabels")
		podLabels := jsonMap(req.Pod, "metadata", "labels")
		isEmptySelector := len(selectorLabels) == 0 && len(jsonSlice(podSelector, "matchExpressions")) == 0
		if isEmptySelector || labelsMatch(podLabels, selectorLabels) {
			hasEgressPolicy = true
			break
		}
	}

	if !hasEgressPolicy {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "cross_ns_egress_controlled",
			Expected:    "== true",
			Actual:      false,
			Description: fmt.Sprintf("Pod '%s'이 NetworkPolicy 없이 cross-namespace 통신 가능", podName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"egress NetworkPolicy로 cross-namespace 통신 통제"}
	}
	return base
}

// ─────────────────────────────────────────────
// 2.6.7 인터넷 접속 통제
// ─────────────────────────────────────────────

// R-2.6.7-POD-01: egress NetworkPolicy 미적용
func evalEgressPolicy(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	podName := jsonStr(req.Pod, "metadata", "name")
	podLabels := jsonMap(req.Pod, "metadata", "labels")

	for _, np := range req.RelatedResources.NetworkPolicies {
		npSpec := jsonMap(np, "spec")
		policyTypes := toStringSlice(npSpec["policyTypes"])
		if !containsStr(policyTypes, "Egress") {
			continue
		}
		egressRules := jsonSlice(npSpec, "egress")
		if len(egressRules) == 0 {
			// deny-all egress — still counts as "egress policy applied"
		}
		podSelector := jsonMap(np, "spec", "podSelector")
		selectorLabels := jsonMap(podSelector, "matchLabels")
		isEmptySelector := len(selectorLabels) == 0 && len(jsonSlice(podSelector, "matchExpressions")) == 0
		if isEmptySelector || labelsMatch(podLabels, selectorLabels) {
			base.Verdict = "준수"
			base.MatchedIndicators = []string{fmt.Sprintf("egress NetworkPolicy '%s' 적용", jsonStr(np, "metadata", "name"))}
			return base
		}
	}

	base.Verdict = "미준수"
	base.Violations = []grc.Violation{{
		Field:       "egress_policy_applied",
		Expected:    "== true",
		Actual:      false,
		Description: fmt.Sprintf("Pod '%s'에 egress NetworkPolicy 미적용 (인터넷 자유 접속)", podName),
		Severity:    "medium",
		K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
	}}
	return base
}

// ─────────────────────────────────────────────
// 2.7.1 암호정책 적용 (추가 룰)
// ─────────────────────────────────────────────

// R-2.7.1-POD-03: 외부 노출 Ingress TLS 미설정
func evalIngressTLS(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	if len(req.RelatedResources.Ingresses) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Ingress 미사용 — 해당 없음"}
		return base
	}

	var violations []grc.Violation
	var matched []string
	for _, ing := range req.RelatedResources.Ingresses {
		ingName := jsonStr(ing, "metadata", "name")
		ingNS := jsonStr(ing, "metadata", "namespace")
		tls := jsonSlice(ing, "spec", "tls")
		if len(tls) == 0 {
			violations = append(violations, grc.Violation{
				Field:       "spec.tls",
				Expected:    "non-empty",
				Actual:      nil,
				Description: fmt.Sprintf("외부 노출 Ingress '%s'에 TLS 미설정 (평문 통신)", ingName),
				Severity:    "high",
				K8sSource:   grc.K8sSource{Namespace: ingNS, ResourceKind: "Ingress", ResourceName: ingName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("Ingress '%s': TLS 설정됨", ingName))
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
// 2.8.3 시험과 운영 환경 분리
// ─────────────────────────────────────────────

// R-2.8.3-POD-02: namespace 내 prod/dev 워크로드 혼재
func evalNSEnvMixing(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	// Gather env labels from namespaces_in_cluster data or workloads
	envs := map[string]bool{}
	// Check current pod's env
	podEnv := strVal(jsonMap(req.Pod, "metadata", "labels")["env"])
	if podEnv != "" {
		envs[podEnv] = true
	}

	// Check workloads in the same namespace
	for _, wl := range req.RelatedResources.Workloads {
		wlNS := jsonStr(wl, "metadata", "namespace")
		if wlNS != podNS {
			continue
		}
		wlEnv := strVal(jsonMap(wl, "metadata", "labels")["env"])
		if wlEnv == "" {
			wlEnv = strVal(jsonMap(wl, "spec", "template", "metadata", "labels")["env"])
		}
		if wlEnv != "" {
			envs[wlEnv] = true
		}
	}

	if len(envs) == 0 {
		// env 라벨이 전무 → 운영/개발 환경 자체를 판별할 수 없다.
		// 단일 네임스페이스라는 사실만으로 "환경 동질성 = 분리 충족"이라 단정하면 안 되며
		// (오히려 운영/비운영 혼재 가능성), 자동 충족(준수) 처리를 금지하고 수동 검토로 넘긴다.
		base.Verdict = grc.VerdictNEEDS_REVIEW
		base.Reason = "env 라벨 부재로 운영/개발 환경 판별 불가 — 단일 네임스페이스 동질성만으로 시험·운영 분리 충족을 단정할 수 없음. 별도 클러스터/VPC/계정 분리 또는 네임스페이스·RBAC·NetworkPolicy 분리 증적으로 수동 확인 필요"
		return base
	}
	if len(envs) >= 2 {
		envList := make([]string, 0, len(envs))
		for e := range envs {
			envList = append(envList, e)
		}
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "namespace_env_homogeneous",
			Expected:    "env count <= 1",
			Actual:      strings.Join(envList, ", "),
			Description: fmt.Sprintf("namespace '%s'에 prod와 dev 워크로드 공존", podNS),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Namespace", ResourceName: podNS},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("namespace '%s' 환경 동질성 확인", podNS)}
	}
	return base
}

// R-2.8.3-POD-03: prod Secret이 dev에서 참조
func evalCrossEnvSecretRef(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "critical"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	podEnv := strVal(jsonMap(req.Pod, "metadata", "labels")["env"])

	if podEnv == "" {
		base.Verdict = "skip"
		base.SkipReason = "Pod에 env 라벨 없음 — 환경 판별 불가"
		return base
	}

	secretRefs := extractPodSecretRefs(req.Pod)
	if len(secretRefs) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Secret 참조 없음"}
		return base
	}

	var violations []grc.Violation
	for _, secretName := range secretRefs {
		for _, sec := range req.RelatedResources.Secrets {
			if jsonStr(sec, "metadata", "name") != secretName {
				continue
			}
			secEnv := strVal(jsonMap(sec, "metadata", "labels")["env"])
			if secEnv == "" {
				violations = append(violations, grc.Violation{
					Field:       "secret_env_label_missing",
					Expected:    "env 라벨 존재",
					Actual:      "env 라벨 없음",
					Description: fmt.Sprintf("Secret '%s'에 env 라벨 미부여 — 환경 분리 검증 불가", secretName),
					Severity:    "high",
					K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Secret", ResourceName: secretName},
				})
			} else if secEnv != podEnv {
				violations = append(violations, grc.Violation{
					Field:       "cross_env_secret_reference",
					Expected:    fmt.Sprintf("Secret env == Pod env (%s)", podEnv),
					Actual:      secEnv,
					Description: fmt.Sprintf("%s Pod '%s'가 %s Secret '%s' 참조", podEnv, podName, secEnv, secretName),
					Severity:    "critical",
					K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Secret", ResourceName: secretName},
				})
			}
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"교차 환경 Secret 참조 없음"}
	}
	return base
}

// ─────────────────────────────────────────────
// 2.9.1 변경관리
// ─────────────────────────────────────────────

// R-2.9.1-POD-02: revisionHistoryLimit=0 (롤백 불가)
func evalRevisionHistoryLimit(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "info"

	// 수집 누락 가드 유지: 컨트롤러 흔적이 있는데 workload 스냅샷이 비어 있으면 NO_DATA.
	if workloadDataMissing(req) {
		return noDataWorkloadResult(base)
	}

	// revisionHistoryLimit은 Deployment 롤백 이력 보존 개수일 뿐,
	// 변경관리(2.9.1)의 본질인 변경 신청·영향분석·승인·시험 절차와 무관하다.
	// 따라서 이 값으로 충족/미충족을 자동 판정하지 않고, 관측값만 부기한 뒤
	// NEEDS_REVIEW로 두어 ITSM/GitOps 변경 결재 등 절차 증적을 수동 확인하도록 한다.
	var observed []string
	for _, wl := range req.RelatedResources.Workloads {
		wlName := jsonStr(wl, "metadata", "name")
		spec := jsonMap(wl, "spec")
		if spec == nil {
			continue
		}
		if rhl, ok := spec["revisionHistoryLimit"]; ok {
			rhlVal := 0
			switch v := rhl.(type) {
			case float64:
				rhlVal = int(v)
			case int:
				rhlVal = v
			}
			observed = append(observed, fmt.Sprintf("%s=%d", wlName, rhlVal))
		} else {
			observed = append(observed, fmt.Sprintf("%s=기본값(10)", wlName))
		}
	}

	base.Verdict = grc.VerdictNEEDS_REVIEW
	reason := "revisionHistoryLimit은 롤백 이력 보존 설정일 뿐 변경관리 절차(신청·영향분석·승인·시험) 증적이 아님 — 변경관리 충족 여부는 ITSM/그룹웨어 변경 결재 또는 GitOps PR·파이프라인 승인 기록으로 수동 확인 필요"
	if len(observed) > 0 {
		reason += " [관측 revisionHistoryLimit: " + strings.Join(observed, ", ") + "]"
	}
	base.Reason = reason
	base.Layer = grc.LayerR
	return base
}

// ─────────────────────────────────────────────
// 2.10.2 클라우드 보안
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// 2.10.3 공개서버 보안
// ─────────────────────────────────────────────

// R-2.10.3-POD-01: LoadBalancer source range 미설정
func evalLBSourceRange(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	var violations []grc.Violation
	var matched []string
	found := false

	for _, svc := range req.RelatedResources.Services {
		if jsonStr(svc, "spec", "type") != "LoadBalancer" {
			continue
		}
		found = true
		svcName := jsonStr(svc, "metadata", "name")
		svcNS := jsonStr(svc, "metadata", "namespace")
		ranges := jsonSlice(svc, "spec", "loadBalancerSourceRanges")
		if len(ranges) == 0 {
			violations = append(violations, grc.Violation{
				Field:       "spec.loadBalancerSourceRanges",
				Expected:    "non-empty",
				Actual:      nil,
				Description: fmt.Sprintf("LB Service '%s'에 source range 미설정 (0.0.0.0/0 전체 공개)", svcName),
				Severity:    "high",
				K8sSource:   grc.K8sSource{Namespace: svcNS, ResourceKind: "Service", ResourceName: svcName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("LB '%s': source range 설정됨", svcName))
		}
	}

	if !found {
		// 위험 종속형: LB가 없으면 source range 노출 위험도 없음 → 실제 준수.
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"LoadBalancer Service 없음 — source range 노출 위험 없음"}
		return base
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

// R-2.10.3-POD-02: 공개 Ingress WAF annotation 부재
func evalIngressWAF(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	if len(req.RelatedResources.Ingresses) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Ingress 미사용 — 해당 없음"}
		return base
	}

	wafKeys := []string{
		"nginx.ingress.kubernetes.io/modsecurity-snippet",
		"alb.ingress.kubernetes.io/wafv2-acl-arn",
		"traefik.ingress.kubernetes.io/middleware",
	}

	var violations []grc.Violation
	var matched []string
	for _, ing := range req.RelatedResources.Ingresses {
		// Only check ingresses with TLS (public-facing)
		tls := jsonSlice(ing, "spec", "tls")
		if len(tls) == 0 {
			continue
		}
		ingName := jsonStr(ing, "metadata", "name")
		ingNS := jsonStr(ing, "metadata", "namespace")
		annotations := jsonMap(ing, "metadata", "annotations")
		hasWAF := false
		for _, key := range wafKeys {
			if v, ok := annotations[key]; ok && strVal(v) != "" {
				hasWAF = true
				matched = append(matched, fmt.Sprintf("Ingress '%s': WAF annotation '%s'", ingName, key))
				break
			}
		}
		if !hasWAF {
			violations = append(violations, grc.Violation{
				Field:       "waf_annotation",
				Expected:    "exists",
				Actual:      nil,
				Description: fmt.Sprintf("공개 Ingress '%s'에 WAF 미적용", ingName),
				Severity:    "high",
				K8sSource:   grc.K8sSource{Namespace: ingNS, ResourceKind: "Ingress", ResourceName: ingName},
			})
		}
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		if len(matched) == 0 {
			matched = []string{"공개(TLS) Ingress 없음 — 해당 없음"}
		}
		base.MatchedIndicators = matched
	}
	return base
}

// R-2.10.3-POD-04: 공개 Ingress rate limit 미설정
func evalIngressRateLimit(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	if len(req.RelatedResources.Ingresses) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Ingress 미사용 — 해당 없음"}
		return base
	}

	rlKeys := []string{
		"nginx.ingress.kubernetes.io/limit-rps",
		"nginx.ingress.kubernetes.io/limit-connections",
		"alb.ingress.kubernetes.io/actions.rate-limit",
	}

	var violations []grc.Violation
	var matched []string
	for _, ing := range req.RelatedResources.Ingresses {
		ingName := jsonStr(ing, "metadata", "name")
		ingNS := jsonStr(ing, "metadata", "namespace")
		annotations := jsonMap(ing, "metadata", "annotations")
		hasRL := false
		for _, key := range rlKeys {
			if v, ok := annotations[key]; ok && strVal(v) != "" {
				hasRL = true
				matched = append(matched, fmt.Sprintf("Ingress '%s': rate-limit '%s'", ingName, key))
				break
			}
		}
		if !hasRL {
			violations = append(violations, grc.Violation{
				Field:       "rate_limit_annotation",
				Expected:    "exists",
				Actual:      nil,
				Description: fmt.Sprintf("공개 Ingress '%s'에 rate limit 미설정", ingName),
				Severity:    "medium",
				K8sSource:   grc.K8sSource{Namespace: ingNS, ResourceKind: "Ingress", ResourceName: ingName},
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
// 2.10.5 정보전송 보안
// ─────────────────────────────────────────────

// R-2.10.5-POD-01: 외부 공개 Ingress TLS 미설정
func evalExternalIngressTLS(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "critical"
	if len(req.RelatedResources.Ingresses) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Ingress 미사용 — 해당 없음"}
		return base
	}

	var violations []grc.Violation
	var matched []string
	for _, ing := range req.RelatedResources.Ingresses {
		ingName := jsonStr(ing, "metadata", "name")
		ingNS := jsonStr(ing, "metadata", "namespace")
		tls := jsonSlice(ing, "spec", "tls")
		if len(tls) == 0 {
			violations = append(violations, grc.Violation{
				Field:       "spec.tls",
				Expected:    "non-empty",
				Actual:      nil,
				Description: fmt.Sprintf("외부 공개 Ingress '%s'이 TLS 미적용 (HTTP 평문)", ingName),
				Severity:    "critical",
				K8sSource:   grc.K8sSource{Namespace: ingNS, ResourceKind: "Ingress", ResourceName: ingName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("Ingress '%s': TLS 적용", ingName))
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
// 2.10.8 패치관리
// ─────────────────────────────────────────────

var kubeletVersionRegex = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

// R-2.10.8-POD-01: Node kubeletVersion EOL
func evalNodeKubeletVersion(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	if len(req.RelatedResources.Nodes) == 0 {
		base.Verdict = "skip"
		base.SkipReason = "Node 데이터 미제공"
		return base
	}

	// Current stable K8s: 1.30 (May 2026). Supported: current-2 = 1.28+
	const minMinor = 28

	var violations []grc.Violation
	var matched []string
	for _, node := range req.RelatedResources.Nodes {
		nodeName := jsonStr(node, "metadata", "name")
		version := jsonStr(node, "status", "nodeInfo", "kubeletVersion")
		m := kubeletVersionRegex.FindStringSubmatch(version)
		if len(m) < 3 {
			violations = append(violations, grc.Violation{
				Field:       "status.nodeInfo.kubeletVersion",
				Expected:    fmt.Sprintf(">= 1.%d", minMinor),
				Actual:      version,
				Description: fmt.Sprintf("Node '%s'의 kubelet 버전 파싱 실패: %s", nodeName, version),
				Severity:    "high",
				K8sSource:   grc.K8sSource{ResourceKind: "Node", ResourceName: nodeName},
			})
			continue
		}
		minor := 0
		fmt.Sscanf(m[2], "%d", &minor)
		if minor < minMinor {
			violations = append(violations, grc.Violation{
				Field:       "status.nodeInfo.kubeletVersion",
				Expected:    fmt.Sprintf(">= 1.%d", minMinor),
				Actual:      version,
				Description: fmt.Sprintf("Node '%s'의 kubelet 버전 %s이 EOL 또는 stable-2 미만", nodeName, version),
				Severity:    "high",
				K8sSource:   grc.K8sSource{ResourceKind: "Node", ResourceName: nodeName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("Node '%s': %s", nodeName, version))
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

var mutableTags = map[string]bool{
	"latest": true, "stable": true, "prod": true, "main": true, "master": true,
}
var semverTagRegex = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?`)

// R-2.10.8-POD-02: 이미지 태그 mutable
func evalImageTagMutable(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	containers := jsonSlice(req.Pod, "spec", "containers")

	var violations []grc.Violation
	var matched []string
	for _, c := range containers {
		cm := toMap(c)
		if cm == nil {
			continue
		}
		cName := strVal(cm["name"])
		image := strVal(cm["image"])

		// digest(@sha256:)가 있으면 immutable — 태그 무관하게 준수
		if strings.Contains(image, "@sha256:") {
			matched = append(matched, fmt.Sprintf("컨테이너 '%s': digest 고정", cName))
			continue
		}

		tag := extractImageTag(image)
		if mutableTags[tag] || tag == "" {
			violations = append(violations, grc.Violation{
				Field:       "containers[].image",
				Expected:    "semver tag",
				Actual:      image,
				Description: fmt.Sprintf("Pod '%s' 컨테이너 '%s' 이미지 태그가 mutable: '%s'", podName, cName, image),
				Severity:    "medium",
				K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName, ContainerName: cName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("컨테이너 '%s': %s", cName, tag))
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

// R-2.10.8-POD-03: 이미지 digest 미고정
func evalImageDigest(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	containers := jsonSlice(req.Pod, "spec", "containers")

	var violations []grc.Violation
	var matched []string
	for _, c := range containers {
		cm := toMap(c)
		if cm == nil {
			continue
		}
		cName := strVal(cm["name"])
		image := strVal(cm["image"])

		// Check if image has @sha256: digest
		if strings.Contains(image, "@sha256:") {
			matched = append(matched, fmt.Sprintf("컨테이너 '%s': digest 고정", cName))
			continue
		}

		// Also check image_digest field
		digest := strVal(cm["image_digest"])
		if strings.HasPrefix(digest, "sha256:") && len(digest) >= 71 {
			matched = append(matched, fmt.Sprintf("컨테이너 '%s': image_digest 존재", cName))
			continue
		}

		violations = append(violations, grc.Violation{
			Field:       "containers[].image",
			Expected:    "contains @sha256:",
			Actual:      image,
			Description: fmt.Sprintf("Pod '%s' 컨테이너 '%s' 이미지 digest 미고정", podName, cName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName, ContainerName: cName},
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
// 2.11.3 이상행위 분석 및 모니터링
// ─────────────────────────────────────────────

// R-2.11.3-POD-01: prod 환경 shell exec 활동
func evalProdShellExec(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "critical"
	podNS := jsonStr(req.Pod, "metadata", "namespace")

	if len(req.RelatedResources.EBPFProcessEvents) == 0 {
		base.Verdict = "skip"
		base.SkipReason = "eBPF process event 데이터 미제공"
		return base
	}

	// Check if namespace is prod
	nsLabels := jsonMap(req.RelatedResources.Namespace, "metadata", "labels")
	nsEnv := strVal(nsLabels["env"])
	if nsEnv != "prod" {
		// 위험 종속형: 운영(prod) 전용 룰 — 비운영 namespace는 점검 범위 외 → 실제 준수.
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("namespace env=%s (운영 아님) — 운영 외 환경, 위험 없음", nsEnv)}
		return base
	}

	shellBinaries := map[string]bool{
		"/bin/sh": true, "/bin/bash": true, "/usr/bin/sh": true,
		"/usr/bin/bash": true, "/bin/zsh": true,
	}

	var violations []grc.Violation
	for _, evt := range req.RelatedResources.EBPFProcessEvents {
		binary := strVal(evt["binary_path"])
		if binary == "" {
			binary = strVal(evt["binary"])
		}
		if !shellBinaries[binary] {
			continue
		}
		evtPod := strVal(evt["pod_name"])
		evtNS := strVal(evt["namespace"])
		if evtNS == "" {
			evtNS = podNS
		}
		ts := strVal(evt["timestamp"])
		violations = append(violations, grc.Violation{
			Field:       "ebpf_process_exec",
			Expected:    "no shell exec in prod",
			Actual:      binary,
			Description: fmt.Sprintf("prod namespace '%s' Pod '%s'에서 shell exec 관찰 (binary=%s, time=%s)", evtNS, evtPod, binary, ts),
			Severity:    "critical",
			K8sSource:   grc.K8sSource{Namespace: evtNS, ResourceKind: "Pod", ResourceName: evtPod},
		})
	}

	if len(violations) > 0 {
		base.Verdict = "미준수"
		base.Violations = violations
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"prod namespace에서 shell exec 미발견"}
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.11.3-POD-03: eBPF 런타임 텔레메트리 수집 가동 확인
//
// ISMS-P 2.11.3 이상행위 분석 및 모니터링 — 이상행위를 탐지하려면 런타임
// 텔레메트리가 실제로 수집되고 있어야 한다. 운영(prod) namespace에 eBPF
// process event가 들어오는지로 모니터링 체계 가동 여부를 검증한다(있으면 준수,
// 없으면 검토필요 = 모니터링 사각지대 가능). 적시 대응 '절차'는 R-2.11.3-GL03에서
// 별도 점검. 참고: DNS/네트워크 흐름 스트림은 현재 per-pod 페이로드 미포함.
// ─────────────────────────────────────────────
func evalEBPFMonitoringCoverage(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"

	// 운영(prod) namespace로 스코프 — 비운영은 적용 제외
	nsLabels := jsonMap(req.RelatedResources.Namespace, "metadata", "labels")
	if strVal(nsLabels["env"]) != "prod" {
		// 위험 종속형: 운영(prod) 전용 룰 — 비운영 namespace는 점검 범위 외 → 실제 준수.
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("namespace env=%s (운영 아님) — 운영 외 환경, 위험 없음", strVal(nsLabels["env"]))}
		return base
	}

	if len(req.RelatedResources.EBPFProcessEvents) > 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("eBPF 런타임 텔레메트리 수집 확인 (process event %d건) — 이상행위 탐지 데이터 확보", len(req.RelatedResources.EBPFProcessEvents))}
		return base
	}

	base.Verdict = grc.VerdictNEEDS_REVIEW
	base.Reason = "운영 namespace에 eBPF 런타임 텔레메트리(process event)가 수집되지 않음 — 이상행위 탐지 사각지대 가능. eBPF 탐지 도구(Tetragon 등) 커버리지·로그 보존정책 확인 필요. (DNS/네트워크 흐름 스트림은 현재 per-pod 평가 페이로드 미포함)"
	return base
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// extractImageTag extracts the tag portion from a container image reference.
func extractImageTag(image string) string {
	// Remove digest if present
	if idx := strings.Index(image, "@"); idx >= 0 {
		image = image[:idx]
	}
	if idx := strings.LastIndex(image, ":"); idx >= 0 {
		return image[idx+1:]
	}
	return "" // no tag = implies :latest
}
