package scoring

// ============================================================================
// ISMS-P 가산 차감 (보완 → ISMS 룰 해소 → Final 가산분 감소)
//
// 배경: ISMS-P 미준수(NOT_MET) 룰은 상3/중2/하1 가중치로 Final(risk_score)에 *가산*된다
//   (service/grc_risk_score.go: ComputePodISMSPAddend → ApplyISMSPToFinalScore).
//   따라서 어떤 보완이 그 미준수의 "근본원인"을 없애면 해당 룰이 충족(MET)으로 바뀌어
//   가산분이 빠진다 — 그만큼 Final이 더 내려간다.
//
// ★ 점수 체계도, 기존 reduction 코어(BuildRemediationItems)도 바꾸지 않는다.
//   여기서는 "보완 버킷 ↔ ISMS 룰" 매핑만 정의하고, 이미 만들어진 항목/그룹에
//   가산 차감(ISMSReduction)을 덧붙인다(읽기·부착 전용).
//
// ── 매핑(strict, 사용자 확정 "명확한 것만") ─────────────────────────────────
// 룰의 실제 점검 근본원인이 보완 버킷과 직접 1:1로 대응하는 것만 감소 대상으로 둔다.
//
//	cve:image   (그룹) ← R-2.10.8-04   Trivy HIGH+ CVE 현황
//	rbac:sa:<sa>(그룹) ← R-2.5.5-01    cluster-admin·와일드카드·클러스터 Secret 접근
//	                    R-2.5.5-02    위험 RBAC verb 조합(exec/attach, secret r/w, escalate/bind/impersonate, nodes/proxy, sa/token)
//	                    R-2.6.3-01    워크로드 생성 권한(pods/deployments/… create) — RBAC 권한 룰
//	mount:pod   (그룹) ← R-2.10.2-01    hostNetwork/hostPID/hostIPC
//	net:isolation(항목)← R-2.6.1-02/03/04, R-2.6.7-01  default-deny/CNI/cross-ns/egress NetworkPolicy
//	sg:inbound-open   ← R-2.6.1-SG01   SG 인바운드 0.0.0.0/0 전체개방
//	sg:remote-port    ← R-2.6.6-01     SG 원격 관리 포트(SSH 22/RDP 3389) 0.0.0.0/0 개방
//	sg:sensitive-port ← R-2.10.3-SG01  SG 민감·관리 포트 외부노출(공개서버 강화)
//
// SG 3룰은 AWS Security Group(account 범위) 조치라 K8s 보완과 별개의 신규 항목으로 만든다.
// 그 외 가산 룰(암호화 2.7.1, 로그 2.9.4, 모니터링 2.11.3, 이미지 태그/digest 고정 2.10.8-02·03,
// default SA 2.5.1-01, 클라우드 PSA 2.10.2-08 등)은 보완 버킷과 1:1 대응이 없어 가산을 유지한다.
//
// ── 해소 시점(사용자 확정 "근본원인 완전 제거 시") ──────────────────────────
// 한 룰을 여러 하위 항목이 만들면(예: CVE 여러 개, 위험 권한 여러 개, host 설정 여러 개)
// 그룹(전부 제거)에만 붙인다 — 개별 항목 하나로는 룰이 안 풀리므로(잔여) 가산이 그대로다.
// net:isolation·SG 항목은 그 항목 하나가 곧 완전한 조치라 항목에 바로 붙인다.
// ============================================================================

// ISMSRuleHit — 이 pod에서 점수에 가산된 ISMS-P 미준수 룰 1건(서비스가 breakdown에서 채움).
type ISMSRuleHit struct {
	RuleID   string  `json:"rule_id"`
	Severity string  `json:"severity"` // 상/중/하
	Weight   float64 `json:"weight"`   // 3/2/1
}

// 해소 버킷 키.
const (
	bucketCVEImage     = "cve:image"
	bucketRBACSA       = "rbac:sa" // 실제 group id = "rbac:sa:"+sa
	bucketMountPod     = "mount:pod"
	bucketNetIsolation = "net:isolation"
	bucketSGInbound    = "sg:inbound-open"
	bucketSGRemote     = "sg:remote-port"
	bucketSGSensitive  = "sg:sensitive-port"
)

// ismsBucket — 점수 가산 ISMS 룰 → 해소 버킷. "" = 감소 비대상(가산 유지).
func ismsBucket(ruleID string) string {
	switch ruleID {
	case "R-2.10.8-04":
		return bucketCVEImage
	case "R-2.5.5-01", "R-2.5.5-02", "R-2.6.3-01":
		return bucketRBACSA
	case "R-2.10.2-01":
		return bucketMountPod
	case "R-2.6.1-02", "R-2.6.1-03", "R-2.6.1-04", "R-2.6.7-01":
		return bucketNetIsolation
	case "R-2.6.1-SG01":
		return bucketSGInbound
	case "R-2.6.6-01":
		return bucketSGRemote
	case "R-2.10.3-SG01":
		return bucketSGSensitive
	}
	return ""
}

// sgItemMeta — SG 신규 보완 항목 표기(K8s 점수에는 영향 없음, ISMS 가산만 차감).
var sgItemMeta = map[string]struct{ text, target string }{
	bucketSGInbound:   {"AWS Security Group 인바운드 0.0.0.0/0 전체개방을 필요한 포트·출처로 제한", "AWS Security Group"},
	bucketSGRemote:    {"AWS Security Group 원격 관리 포트(SSH 22/RDP 3389) 0.0.0.0/0 개방 차단", "AWS Security Group"},
	bucketSGSensitive: {"AWS Security Group 민감·관리 포트 외부 노출 차단(공개서버 강화)", "AWS Security Group"},
}

// AttachISMSReductions — 이 pod의 가산 룰(fired)을 버킷별로 모아, set의 해당 그룹/항목에
// ISMS 가산 차감(ISMSReduction)을 부착한다. 대응 캐리어(그룹/항목)가 없으면 최소 캐리어를 만든다.
//
//	fired     : 이 pod에서 NOT_MET·점수 가산된 ISMS 룰 (직접+상속)
//	saName    : rbac 그룹 id 구성용("rbac:sa:"+saName)
//	addend    : 현재 ISMS 가산 총합(=breakdown.Addend, before 표기)
//	riskShown : 현재 표시 risk_score (SG 신규항목의 native before 표기용 — 점수 영향 0)
func AttachISMSReductions(set *RemediationSet, fired []ISMSRuleHit, saName string, addend, riskShown float64) {
	if set == nil || len(fired) == 0 {
		return
	}

	// 버킷별 가중치 합 + 룰 목록
	type agg struct {
		sum   float64
		rules []ISMSRuleHit
	}
	buckets := map[string]*agg{}
	order := []string{} // 출력 안정성(결정적 순서)
	for _, r := range fired {
		b := ismsBucket(r.RuleID)
		if b == "" {
			continue // strict 매핑 비대상 → 가산 유지
		}
		a := buckets[b]
		if a == nil {
			a = &agg{}
			buckets[b] = a
			order = append(order, b)
		}
		a.sum += r.Weight
		a.rules = append(a.rules, r)
	}
	if len(buckets) == 0 {
		return
	}

	mkRR := func(sum float64) *RiskReduction {
		after := addend - sum
		if after < 0 {
			after = 0
		}
		return &RiskReduction{Axis: AxisRisk, Before: RoundTo2(addend), After: RoundTo2(after), Delta: RoundTo2(sum)}
	}
	// 기존 캐리어(group/item)에 부착. 슬라이스는 backing array 공유라 in-place 반영됨.
	attach := func(items []RemediationItem, id string, a *agg) bool {
		for i := range items {
			if items[i].ID == id {
				items[i].ISMSReduction = mkRR(a.sum)
				items[i].ISMSRules = a.rules
				return true
			}
		}
		return false
	}

	for _, b := range order {
		a := buckets[b]
		switch b {
		case bucketCVEImage:
			if !attach(set.Groups, bucketCVEImage, a) {
				set.Groups = append(set.Groups, ismsCarrier(bucketCVEImage, "cve", "image",
					"이미지를 패치 버전으로 업그레이드(전체 CVE 해소)", riskShown, mkRR(a.sum), a.rules))
			}
		case bucketMountPod:
			if !attach(set.Groups, bucketMountPod, a) {
				set.Groups = append(set.Groups, ismsCarrier(bucketMountPod, "mount", "pod",
					"privileged·hostPath·host* 전부 제거", riskShown, mkRR(a.sum), a.rules))
			}
		case bucketRBACSA:
			id := bucketRBACSA + ":" + saName
			if !attach(set.Groups, id, a) {
				set.Groups = append(set.Groups, ismsCarrier(id, "rbac", "SA "+saName,
					"이 SA의 위험 권한 전부 회수", riskShown, mkRR(a.sum), a.rules))
			}
		case bucketNetIsolation:
			if !attach(set.Items, bucketNetIsolation, a) {
				set.Items = append(set.Items, ismsCarrier(bucketNetIsolation, "net", "pod",
					"default-deny NetworkPolicy 적용(네트워크 접근통제)", riskShown, mkRR(a.sum), a.rules))
			}
		case bucketSGInbound, bucketSGRemote, bucketSGSensitive:
			meta := sgItemMeta[b]
			set.Items = append(set.Items, ismsCarrier(b, "net", meta.target, meta.text, riskShown, mkRR(a.sum), a.rules))
		}
	}
}

// ismsCarrier — VARA 기본 점수 영향이 없는(=ISMS 가산만 차감하는) 보완 항목/그룹 캐리어.
// native RiskReduction은 delta 0(기본 점수 불변), 실제 효과는 ISMSReduction에 담는다.
func ismsCarrier(id, kind, target, text string, riskShown float64, rr *RiskReduction, rules []ISMSRuleHit) RemediationItem {
	return RemediationItem{
		ID: id, Kind: kind, Target: target, Text: text,
		RiskReduction: RiskReduction{Axis: AxisRisk, Before: RoundTo2(riskShown), After: RoundTo2(riskShown), Delta: 0},
		ISMSReduction: rr, ISMSRules: rules,
	}
}
