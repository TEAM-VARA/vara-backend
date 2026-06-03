package service

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// ─────────────────────────────────────────────
// 1.2.2 현황 및 흐름분석
// ─────────────────────────────────────────────

// R-1.2.2-POD-01: ExternalName Service에 외부 의존성 라벨 부재
func evalExternalDepLabel(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	var violations []grc.Violation
	var matched []string
	found := false

	for _, svc := range req.RelatedResources.Services {
		specType := jsonStr(svc, "spec", "type")
		if specType != "ExternalName" {
			continue
		}
		found = true
		svcName := jsonStr(svc, "metadata", "name")
		labels := jsonMap(svc, "metadata", "labels")
		if _, ok := labels["isms-p/external-dep"]; !ok {
			violations = append(violations, grc.Violation{
				Field:       "metadata.labels.isms-p/external-dep",
				Expected:    "exists",
				Actual:      nil,
				Description: fmt.Sprintf("ExternalName Service '%s'에 외부 의존성 라벨 부재", svcName),
				Severity:    "medium",
				K8sSource:   grc.K8sSource{Namespace: jsonStr(svc, "metadata", "namespace"), ResourceKind: "Service", ResourceName: svcName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("Service '%s': isms-p/external-dep 존재", svcName))
		}
	}

	if !found {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"ExternalName Service 없음 — 해당 없음"}
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

// R-1.2.2-POD-02: Ingress 흐름도 등록 annotation 부재
func evalIngressFlowRegistered(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "low"
	if len(req.RelatedResources.Ingresses) == 0 {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Ingress 미사용 — 해당 없음"}
		return base
	}

	var violations []grc.Violation
	var matched []string
	for _, ing := range req.RelatedResources.Ingresses {
		ingName := jsonStr(ing, "metadata", "name")
		annotations := jsonMap(ing, "metadata", "annotations")
		if _, ok := annotations["isms-p/flow-registered"]; !ok {
			violations = append(violations, grc.Violation{
				Field:       "metadata.annotations.isms-p/flow-registered",
				Expected:    "exists",
				Actual:      nil,
				Description: fmt.Sprintf("Ingress '%s'이 흐름도에 미등록", ingName),
				Severity:    "low",
				K8sSource:   grc.K8sSource{Namespace: jsonStr(ing, "metadata", "namespace"), ResourceKind: "Ingress", ResourceName: ingName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("Ingress '%s': flow-registered 존재", ingName))
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
// 2.1.3 정보자산 관리
// ─────────────────────────────────────────────

// R-2.1.3-POD-01: 워크로드 owner/contact annotation 부재
func evalWorkloadOwnerAnnotation(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	annotations := jsonMap(req.Pod, "metadata", "annotations")

	hasOwner := false
	for _, key := range []string{"owner", "contact"} {
		if v, ok := annotations[key]; ok && strVal(v) != "" {
			hasOwner = true
			break
		}
	}

	if !hasOwner {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "metadata.annotations.owner|contact",
			Expected:    "exists",
			Actual:      nil,
			Description: fmt.Sprintf("워크로드 '%s'에 책임자(owner/contact) annotation 부재", podName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"owner/contact annotation 존재"}
	}
	return base
}

// R-2.1.3-POD-02: security-class 라벨 부재
func evalSecurityClassLabel(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	labels := jsonMap(req.Pod, "metadata", "labels")

	val := strVal(labels["security-class"])
	allowed := map[string]bool{"high": true, "medium": true, "low": true}

	if !allowed[val] {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "metadata.labels.security-class",
			Expected:    "in [high, medium, low]",
			Actual:      val,
			Description: fmt.Sprintf("워크로드 '%s'에 security-class 라벨 부재 또는 허용 외 값", podName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("security-class=%s", val)}
	}
	return base
}

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

// R-2.5.1-POD-02: ServiceAccount owner/team 라벨 부재
func evalSAOwnerLabel(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" || saName == "default" {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"default SA — 별도 점검 불필요"}
		return base
	}

	podNS := jsonStr(req.Pod, "metadata", "namespace")
	var targetSA map[string]any
	for _, sa := range req.RelatedResources.ServiceAccounts {
		if jsonStr(sa, "metadata", "name") == saName && jsonStr(sa, "metadata", "namespace") == podNS {
			targetSA = sa
			break
		}
	}

	if targetSA == nil {
		base.Verdict = "skip"
		base.SkipReason = fmt.Sprintf("SA '%s' 데이터 미제공", saName)
		return base
	}

	labels := jsonMap(targetSA, "metadata", "labels")
	hasLabel := false
	for _, key := range []string{"owner", "team"} {
		if v, ok := labels[key]; ok && strVal(v) != "" {
			hasLabel = true
			break
		}
	}

	if !hasLabel {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "metadata.labels.owner|team",
			Expected:    "exists",
			Actual:      nil,
			Description: fmt.Sprintf("SA '%s/%s'에 owner/team 라벨 부재", podNS, saName),
			Severity:    "medium",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "ServiceAccount", ResourceName: saName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("SA '%s' owner/team 라벨 존재", saName)}
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

var predictableSARegex = regexp.MustCompile(`^(admin|root|test|temp|guest)(-.*)?$`)
var genericSARegex = regexp.MustCompile(`^(user|account|sa)[0-9]+$`)

// R-2.5.2-POD-01: 추측 가능한 SA 이름
func evalPredictableSAName(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	saName := jsonStr(req.Pod, "spec", "serviceAccountName")
	if saName == "" {
		saName = "default"
	}
	podNS := jsonStr(req.Pod, "metadata", "namespace")

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

// R-2.8.3-POD-01: 워크로드 env 라벨 부재
func evalWorkloadEnvLabel(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	podName := jsonStr(req.Pod, "metadata", "name")
	podNS := jsonStr(req.Pod, "metadata", "namespace")
	labels := jsonMap(req.Pod, "metadata", "labels")

	val := strVal(labels["env"])
	allowed := map[string]bool{"prod": true, "stg": true, "dev": true, "test": true}

	if !allowed[val] {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "metadata.labels.env",
			Expected:    "in [prod, stg, dev, test]",
			Actual:      val,
			Description: fmt.Sprintf("워크로드 '%s'에 env 라벨 부재 또는 허용 외 값", podName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: podNS, ResourceKind: "Pod", ResourceName: podName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("env=%s", val)}
	}
	return base
}

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

// R-2.9.1-POD-01: change-cause annotation 부재
func evalChangeCause(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	var violations []grc.Violation
	var matched []string
	found := false

	for _, wl := range req.RelatedResources.Workloads {
		kind := jsonStr(wl, "kind")
		if kind != "" && kind != "Deployment" {
			continue
		}
		found = true
		wlName := jsonStr(wl, "metadata", "name")
		wlNS := jsonStr(wl, "metadata", "namespace")
		annotations := jsonMap(wl, "metadata", "annotations")
		changeCause := strVal(annotations["kubernetes.io/change-cause"])
		if changeCause == "" {
			violations = append(violations, grc.Violation{
				Field:       "metadata.annotations.kubernetes.io/change-cause",
				Expected:    "non-empty",
				Actual:      nil,
				Description: fmt.Sprintf("Deployment '%s'에 변경 사유(change-cause) 미기록", wlName),
				Severity:    "medium",
				K8sSource:   grc.K8sSource{Namespace: wlNS, ResourceKind: "Deployment", ResourceName: wlName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("Deployment '%s': change-cause 존재", wlName))
		}
	}

	if !found {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"Deployment 워크로드 없음 — 해당 없음"}
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

// R-2.9.1-POD-02: revisionHistoryLimit=0 (롤백 불가)
func evalRevisionHistoryLimit(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	var violations []grc.Violation
	var matched []string
	found := false

	for _, wl := range req.RelatedResources.Workloads {
		found = true
		wlName := jsonStr(wl, "metadata", "name")
		wlNS := jsonStr(wl, "metadata", "namespace")
		spec := jsonMap(wl, "spec")
		if spec == nil {
			continue
		}
		rhl, ok := spec["revisionHistoryLimit"]
		if !ok {
			// Default is 10, which is fine
			matched = append(matched, fmt.Sprintf("'%s': revisionHistoryLimit 기본값 (10)", wlName))
			continue
		}
		rhlVal := 0
		switch v := rhl.(type) {
		case float64:
			rhlVal = int(v)
		case int:
			rhlVal = v
		}
		if rhlVal == 0 {
			violations = append(violations, grc.Violation{
				Field:       "spec.revisionHistoryLimit",
				Expected:    "> 0",
				Actual:      0,
				Description: fmt.Sprintf("워크로드 '%s'의 revisionHistoryLimit=0 (롤백 불가)", wlName),
				Severity:    "high",
				K8sSource:   grc.K8sSource{Namespace: wlNS, ResourceKind: "Deployment", ResourceName: wlName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("'%s': revisionHistoryLimit=%d", wlName, rhlVal))
		}
	}

	if !found {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"워크로드 없음 — 해당 없음"}
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

// ─────────────────────────────────────────────
// 2.10.2 클라우드 보안
// ─────────────────────────────────────────────

// R-2.10.2-POD-08: Namespace Pod Security Admission 라벨 부재
func evalNamespacePSA(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	ns := req.RelatedResources.Namespace
	nsName := jsonStr(ns, "metadata", "name")
	nsLabels := jsonMap(ns, "metadata", "labels")

	enforce := strVal(nsLabels["pod-security.kubernetes.io/enforce"])
	allowed := map[string]bool{"restricted": true, "baseline": true}

	if !allowed[enforce] {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Field:       "metadata.labels.pod-security.kubernetes.io/enforce",
			Expected:    "in [restricted, baseline]",
			Actual:      enforce,
			Description: fmt.Sprintf("namespace '%s'에 PSA enforce 라벨 부재 (보안 컨텍스트 강제 정책 없음)", nsName),
			Severity:    "high",
			K8sSource:   grc.K8sSource{Namespace: nsName, ResourceKind: "Namespace", ResourceName: nsName},
		}}
	} else {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("PSA enforce=%s", enforce)}
	}
	return base
}

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
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"LoadBalancer Service 없음 — 해당 없음"}
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

// R-2.10.3-POD-03: NodePort Service 공개 의도 라벨 부재
func evalNodePortExposureLabel(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
	var violations []grc.Violation
	var matched []string
	found := false

	for _, svc := range req.RelatedResources.Services {
		if jsonStr(svc, "spec", "type") != "NodePort" {
			continue
		}
		found = true
		svcName := jsonStr(svc, "metadata", "name")
		svcNS := jsonStr(svc, "metadata", "namespace")
		labels := jsonMap(svc, "metadata", "labels")
		if strVal(labels["isms-p/exposure"]) != "public" {
			violations = append(violations, grc.Violation{
				Field:       "metadata.labels.isms-p/exposure",
				Expected:    "== public",
				Actual:      strVal(labels["isms-p/exposure"]),
				Description: fmt.Sprintf("NodePort Service '%s'에 공개 의도 라벨 부재", svcName),
				Severity:    "medium",
				K8sSource:   grc.K8sSource{Namespace: svcNS, ResourceKind: "Service", ResourceName: svcName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("NodePort '%s': exposure=public", svcName))
		}
	}

	if !found {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"NodePort Service 없음 — 해당 없음"}
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

// R-2.10.3-POD-05: LoadBalancer 공개 의도 라벨 부재
func evalLBExposureLabel(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "medium"
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
		labels := jsonMap(svc, "metadata", "labels")
		if strVal(labels["isms-p/exposure"]) != "public" {
			violations = append(violations, grc.Violation{
				Field:       "metadata.labels.isms-p/exposure",
				Expected:    "== public",
				Actual:      strVal(labels["isms-p/exposure"]),
				Description: fmt.Sprintf("LoadBalancer Service '%s'에 공개 의도 라벨 부재", svcName),
				Severity:    "medium",
				K8sSource:   grc.K8sSource{Namespace: svcNS, ResourceKind: "Service", ResourceName: svcName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("LB '%s': exposure=public", svcName))
		}
	}

	if !found {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"LoadBalancer Service 없음 — 해당 없음"}
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

// R-2.10.5-POD-03: ExternalName Service 평문 endpoint
func evalExternalNamePlaintext(_ Rule, req PodGraphRequest, base PodRuleResult) PodRuleResult {
	base.Severity = "high"
	var violations []grc.Violation
	var matched []string
	found := false

	for _, svc := range req.RelatedResources.Services {
		if jsonStr(svc, "spec", "type") != "ExternalName" {
			continue
		}
		found = true
		svcName := jsonStr(svc, "metadata", "name")
		svcNS := jsonStr(svc, "metadata", "namespace")
		externalName := jsonStr(svc, "spec", "externalName")
		if strings.HasPrefix(externalName, "http://") {
			violations = append(violations, grc.Violation{
				Field:       "spec.externalName",
				Expected:    "not start with http://",
				Actual:      externalName,
				Description: fmt.Sprintf("ExternalName Service '%s'의 endpoint가 http:// 평문", svcName),
				Severity:    "high",
				K8sSource:   grc.K8sSource{Namespace: svcNS, ResourceKind: "Service", ResourceName: svcName},
			})
		} else {
			matched = append(matched, fmt.Sprintf("ExternalName '%s': 평문 아님", svcName))
		}
	}

	if !found {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{"ExternalName Service 없음 — 해당 없음"}
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
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("namespace env=%s (prod 아님) — 해당 없음", nsEnv)}
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
