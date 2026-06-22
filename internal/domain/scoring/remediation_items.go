package scoring

import (
	"fmt"
	"sort"
)

// ============================================================================
// Granular 보완 항목 + 항목별 점수 하락 (remediation reduction)
//
// ★ 기존 점수 함수(ComputeRBACScore/ComputeMountScore/ComputeGlobalScore/
//   ComputeFinalScore/ComputeLocalScore)는 절대 수정하지 않는다. 여기서는 그 함수들을
//   "읽기"로만 재사용해, 항목 하나를 빼고 남은 것으로 재계산한 차이를 보여줄 뿐이다.
//
// 모델(전부 MAX/tier 유지):
//   per-item delta = (현재 점수) − (그 항목 1개 빼고 남은 것으로 재계산한 점수)
//   - CVE  : Global = CVE 최댓값 → 그 CVE 빼고 남은 max
//   - RBAC : level = 최고 1개   → 그 권한 빼고 남은 perms로 level 재산정 (상위 포함시 Δ=0)
//   - Mount: tier 30 = host*/privileged/hostPath 중 하나라도 → 그거 끄고 재산정 (다른 trigger 남으면 Δ=0)
//   axis: CVE·노출 = risk, RBAC·Mount·net격리 = impact
// ============================================================================

// RemediationItem — 가장 작은 단위의 보완 + 그것만 고쳤을 때 점수 하락.
type RemediationItem struct {
	ID            string        `json:"id"`              // cve:CVE-… / rbac:verb:resource / mount:setting:target / net:…
	Kind          string        `json:"kind"`            // cve|rbac|mount|net
	Target        string        `json:"target,omitempty"`
	Text          string        `json:"text"`
	Severity      string        `json:"severity,omitempty"` // 참고용 정렬(critical|high|medium|low) — 점수와 무관
	GroupID       string        `json:"group_id,omitempty"`
	RiskReduction RiskReduction `json:"risk_reduction"`     // axis/before/after/delta (VARA 기본 점수)
	ZeroReason    string        `json:"zero_reason,omitempty"` // delta=0 사유(상위 포함 / 더 심한 항목 존재 / 같은 등급 잔존)

	// ISMS-P 가산 차감 — 이 보완이 ISMS 미준수 룰의 근본원인을 없애 Final 가산분이 빠지는 양.
	// 점수 체계는 불변. 그룹(근본원인 완전 제거)에만 붙고, 개별 항목은 잔여라 비어 있음(nil).
	// AttachISMSReductions가 채운다. axis=risk(Final), before/after=ISMS 가산 총합 기준.
	ISMSReduction *RiskReduction `json:"isms_reduction,omitempty"`
	ISMSRules     []ISMSRuleHit  `json:"isms_rules,omitempty"` // 이 보완으로 해소되는 ISMS 룰
}

// 입력(전부 plain data — repo 결합 없음). 서비스가 채워 넣는다.
type CVEItem struct {
	ID       string  // CVE-2025-1234
	Score    float64 // 이 CVE의 global score (0~100)
	Severity string
	Fixed    string // 패치 버전(있으면)
}

type PermItem struct {
	Verb, Resource, Namespace string
	Severity                  string
}

type RemediationInput struct {
	// 표시용 현재 점수(앵커)
	RiskScore   float64 // 현재 Final(risk_score)
	ImpactScore float64 // 현재 attack_path total
	Toxic       float64

	// risk 축 소스
	GlobalImage float64   // 현재 = CVE 최댓값
	CVEs        []CVEItem // 이미지 CVE 전체(가능하면 점수 내림차순)
	Exposed     bool
	ExposedVia  string

	// impact 축 소스
	RBAC, Network, Mount int        // 현재 sub-score
	AllPerms             []PermItem // 그 SA의 최종 권한 전체(rbac_sa_permissions)
	PrivilegedContainers []string
	HostPathVolumes      []string
	HostNetwork, HostPID bool
	NetworkIsolationNone bool // 9034 해당(격리 없음)

	SAName string // group target 표기용
}

// RemediationSet — 개별 항목 + 묶음(그룹).
type RemediationSet struct {
	Items  []RemediationItem `json:"items"`
	Groups []RemediationItem `json:"groups"`
}

// BuildRemediationItems — 입력 신호 → granular 항목 + 그룹.
func BuildRemediationItems(in RemediationInput) RemediationSet {
	var set RemediationSet
	toxic := in.Toxic
	if toxic <= 0 {
		toxic = FinalDefaultToxicMultiplier
	}

	// ── risk 축 베이스 ──
	curRisk := RiskInputs{GlobalImage: in.GlobalImage, Exposed: in.Exposed, Toxic: toxic}
	riskShown := in.RiskScore
	riskCalc := curRisk.Score()
	mkRisk := func(afterScore float64) RiskReduction {
		delta := riskCalc - afterScore
		if delta < 0 {
			delta = 0
		}
		af := riskShown - delta
		if af < 0 {
			af = 0
		}
		return RiskReduction{Axis: AxisRisk, Before: RoundTo2(riskShown), After: RoundTo2(af), Delta: RoundTo2(delta)}
	}

	// ── impact 축 베이스 ──
	impactBefore := float64(clampInt(in.RBAC+in.Network+in.Mount, 0, AttackPathMaxTotal))
	mkImpact := func(afterScore float64) RiskReduction {
		delta := impactBefore - afterScore
		if delta < 0 {
			delta = 0
		}
		return RiskReduction{Axis: AxisImpact, Before: RoundTo2(impactBefore), After: RoundTo2(afterScore), Delta: RoundTo2(delta)}
	}

	// ───────── CVE 항목 (risk 축, Global=MAX) ─────────
	if len(in.CVEs) > 0 {
		cves := append([]CVEItem(nil), in.CVEs...)
		sort.SliceStable(cves, func(i, j int) bool { return cves[i].Score > cves[j].Score })
		for _, c := range cves {
			afterGlobal := maxCVEExcept(cves, c.ID)
			after := curRisk
			after.GlobalImage = afterGlobal
			rr := mkRisk(after.Score())
			item := RemediationItem{
				ID: "cve:" + c.ID, Kind: "cve", Target: "image",
				Text: cveText(c), Severity: c.Severity, GroupID: "cve:image",
				RiskReduction: rr,
			}
			if rr.Delta == 0 {
				item.ZeroReason = "더 심한 CVE가 있어 단독 패치로는 점수(최악 CVE 기준)가 안 바뀜"
			}
			set.Items = append(set.Items, item)
		}
		// 그룹: 이미지 업그레이드 = 모든 CVE 제거 → Global 0
		after := curRisk
		after.GlobalImage = 0
		set.Groups = append(set.Groups, RemediationItem{
			ID: "cve:image", Kind: "cve", Target: "image", Text: "이미지를 패치 버전으로 업그레이드(전체 CVE 해소)",
			RiskReduction: mkRisk(after.Score()),
		})
	}

	// ───────── 노출 (risk 축) ─────────
	if in.Exposed {
		after := curRisk
		after.Exposed = false
		via := in.ExposedVia
		if via == "" {
			via = "외부 노출"
		}
		set.Items = append(set.Items, RemediationItem{
			ID: "net:exposure", Kind: "net", Target: via, Text: "외부 노출 차단(Service/Ingress 제거·인증)",
			Severity: "high", RiskReduction: mkRisk(after.Score()),
		})
	}

	// ───────── RBAC 항목 (impact 축, level=MAX) ─────────
	riskyPerms := filterRisky(in.AllPerms)
	if len(riskyPerms) > 0 {
		for _, p := range riskyPerms {
			afterRBAC := rbacLevelFromPerms(removePerm(in.AllPerms, p))
			rr := mkImpact(float64(clampInt(afterRBAC+in.Network+in.Mount, 0, AttackPathMaxTotal)))
			item := RemediationItem{
				ID: permID(p), Kind: "rbac", Target: rbacTarget(in.SAName, p),
				Text: fmt.Sprintf("%s %s 권한 회수", p.Verb, permResource(p)),
				Severity: p.Severity, GroupID: "rbac:sa:" + in.SAName,
				RiskReduction: rr,
			}
			if rr.Delta == 0 {
				item.ZeroReason = "상위 권한(cluster-admin/wildcard 등)에 포함됨 — 그 상위부터 회수해야 점수 하락"
			}
			set.Items = append(set.Items, item)
		}
		// 그룹: 위험 권한 전부 회수
		afterRBAC := rbacLevelFromPerms(removeAll(in.AllPerms, riskyPerms))
		set.Groups = append(set.Groups, RemediationItem{
			ID: "rbac:sa:" + in.SAName, Kind: "rbac", Target: "SA " + in.SAName, Text: "이 SA의 위험 권한 전부 회수",
			RiskReduction: mkImpact(float64(clampInt(afterRBAC+in.Network+in.Mount, 0, AttackPathMaxTotal))),
		})
	}

	// ───────── Mount 항목 (impact 축, tier=MAX) ─────────
	curMD := MountDetails{
		HostNetwork: in.HostNetwork, HostPID: in.HostPID,
		HasHostPath: len(in.HostPathVolumes) > 0, HasPrivileged: len(in.PrivilegedContainers) > 0,
	}
	mountItem := func(id, target, text, sev string, off func(*MountDetails)) RemediationItem {
		md := curMD
		off(&md)
		afterMount := ComputeMountScore(md)
		rr := mkImpact(float64(clampInt(in.RBAC+in.Network+afterMount, 0, AttackPathMaxTotal)))
		it := RemediationItem{ID: id, Kind: "mount", Target: target, Text: text, Severity: sev, GroupID: "mount:pod", RiskReduction: rr}
		if rr.Delta == 0 {
			it.ZeroReason = "같은 등급(30)을 만드는 다른 host 설정이 남아 있음 — 함께 제거해야"
		}
		return it
	}
	for _, c := range in.PrivilegedContainers {
		set.Items = append(set.Items, mountItem("mount:privileged:"+c, "container "+c,
			fmt.Sprintf("컨테이너 '%s' privileged 제거", c), "high",
			func(m *MountDetails) { m.HasPrivileged = false }))
	}
	for _, v := range in.HostPathVolumes {
		set.Items = append(set.Items, mountItem("mount:hostPath:"+v, "volume "+v,
			fmt.Sprintf("hostPath 볼륨 '%s' 제거(또는 readOnly)", v), "high",
			func(m *MountDetails) { m.HasHostPath = false }))
	}
	if in.HostNetwork {
		set.Items = append(set.Items, mountItem("mount:hostNetwork:pod", "pod",
			"hostNetwork 비활성화", "medium", func(m *MountDetails) { m.HostNetwork = false }))
	}
	if in.HostPID {
		set.Items = append(set.Items, mountItem("mount:hostPID:pod", "pod",
			"hostPID 비활성화", "medium", func(m *MountDetails) { m.HostPID = false }))
	}
	// Mount 그룹: 모든 host*/privileged/hostPath 제거 → tier 하락
	if curMD.HasPrivileged || curMD.HasHostPath || curMD.HostNetwork || curMD.HostPID {
		md := curMD
		md.HasPrivileged, md.HasHostPath, md.HostNetwork, md.HostPID = false, false, false, false
		set.Groups = append(set.Groups, RemediationItem{
			ID: "mount:pod", Kind: "mount", Target: "pod", Text: "privileged·hostPath·host* 전부 제거",
			RiskReduction: mkImpact(float64(clampInt(in.RBAC+in.Network+ComputeMountScore(md), 0, AttackPathMaxTotal))),
		})
	}

	// ───────── network isolation (impact 축, 9034) ─────────
	if in.NetworkIsolationNone {
		afterNet := ComputeNetworkScore(NetworkIsolationDenyAll) // 0
		set.Items = append(set.Items, RemediationItem{
			ID: "net:isolation", Kind: "net", Target: "pod", Text: "default-deny NetworkPolicy 적용", Severity: "high",
			RiskReduction: mkImpact(float64(clampInt(in.RBAC+afterNet+in.Mount, 0, AttackPathMaxTotal))),
		})
	}

	return set
}

// ── 순수 헬퍼 ──

// rbacLevelFromPerms — 권한 목록 → RBAC level 점수(기존 attack_path switch와 동일 우선순위).
// perms 비면 0(none). 기존 ComputeRBACScore를 그대로 재사용.
func rbacLevelFromPerms(perms []PermItem) int {
	if len(perms) == 0 {
		return ComputeRBACScore(RBACLevelNone)
	}
	cadmin, wild, secrets, exec, any := false, false, false, false, false
	for _, p := range perms {
		any = true
		switch {
		case p.Verb == "*" && p.Resource == "*":
			cadmin = true
		case p.Verb == "*" || p.Resource == "*":
			wild = true
		case p.Resource == "secrets" && (p.Verb == "get" || p.Verb == "list" || p.Verb == "watch"):
			secrets = true
		case (p.Resource == "pods/exec" || p.Resource == "pods/attach") && p.Verb == "create":
			exec = true
		}
	}
	switch {
	case cadmin:
		return ComputeRBACScore(RBACLevelClusterAdmin)
	case wild:
		return ComputeRBACScore(RBACLevelWildcard)
	case secrets:
		return ComputeRBACScore(RBACLevelSecretsAccess)
	case exec:
		return ComputeRBACScore(RBACLevelPodExec)
	case any:
		return ComputeRBACScore(RBACLevelReadOnly)
	default:
		return ComputeRBACScore(RBACLevelNone)
	}
}

func isRiskyPerm(p PermItem) bool {
	switch {
	case p.Verb == "*" || p.Resource == "*":
		return true
	case p.Resource == "secrets" && (p.Verb == "get" || p.Verb == "list" || p.Verb == "watch"):
		return true
	case (p.Resource == "pods/exec" || p.Resource == "pods/attach") && p.Verb == "create":
		return true
	case p.Resource == "pods" && p.Verb == "create":
		return true
	case (p.Resource == "rolebindings" || p.Resource == "clusterrolebindings") && (p.Verb == "create" || p.Verb == "bind"):
		return true
	case (p.Resource == "roles" || p.Resource == "clusterroles") && (p.Verb == "bind" || p.Verb == "escalate"):
		return true
	case p.Verb == "impersonate":
		return true
	case p.Resource == "nodes/proxy":
		return true
	}
	return false
}

func filterRisky(perms []PermItem) []PermItem {
	var out []PermItem
	for _, p := range perms {
		if isRiskyPerm(p) {
			out = append(out, p)
		}
	}
	return out
}

func samePerm(a, b PermItem) bool {
	return a.Verb == b.Verb && a.Resource == b.Resource && a.Namespace == b.Namespace
}

func removePerm(perms []PermItem, drop PermItem) []PermItem {
	out := make([]PermItem, 0, len(perms))
	for _, p := range perms {
		if !samePerm(p, drop) {
			out = append(out, p)
		}
	}
	return out
}

func removeAll(perms, drop []PermItem) []PermItem {
	out := make([]PermItem, 0, len(perms))
	for _, p := range perms {
		skip := false
		for _, d := range drop {
			if samePerm(p, d) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

func maxCVEExcept(cves []CVEItem, exceptID string) float64 {
	m := 0.0
	for _, c := range cves {
		if c.ID == exceptID {
			continue
		}
		if c.Score > m {
			m = c.Score
		}
	}
	return m
}

func permResource(p PermItem) string {
	if p.Namespace != "" {
		return p.Resource + " @ns=" + p.Namespace
	}
	return p.Resource
}

func permID(p PermItem) string {
	id := "rbac:" + p.Verb + ":" + p.Resource
	if p.Namespace != "" {
		id += ":" + p.Namespace
	}
	return id
}

func rbacTarget(sa string, p PermItem) string {
	if sa == "" {
		return "SA"
	}
	return "SA " + sa
}

func cveText(c CVEItem) string {
	t := c.ID
	if c.Score > 0 {
		t += fmt.Sprintf("(점수 %.0f)", c.Score)
	}
	if c.Fixed != "" {
		t += " → " + c.Fixed + " 업그레이드"
	} else {
		t += " 패치"
	}
	return t
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
