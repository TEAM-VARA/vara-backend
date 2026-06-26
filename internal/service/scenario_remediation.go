package service

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/vara/backend/internal/blastedge"
	"github.com/vara/backend/internal/domain/scoring"
)

// buildRemediation — granular 보완 항목/그룹(remediation_items)을 만들어 res에 채운다.
//
// 기존 점수 함수(ComputeRBACScore/ComputeMountScore/ComputeGlobalScore/ComputeFinalScore)는
// 일절 수정하지 않고, 데이터만 모아 순수 함수 scoring.BuildRemediationItems에 넘긴다.
// (= "원래 risk scoring은 그대로, reduction만" 요구 충족)
func (s *ScenarioService) buildRemediation(ctx context.Context, companyID, cluster, podUID string, res *scoring.PodScenarioResult) {
	if s.attackPath == nil || s.finalScore == nil || res == nil {
		return
	}
	ap, err := s.attackPath.GetByPodUID(ctx, cluster, podUID)
	if err != nil || ap == nil {
		return
	}
	fin, ferr := s.finalScore.GetByPodUID(ctx, cluster, podUID)
	if ferr != nil || fin == nil {
		return
	}

	in := scoring.RemediationInput{
		RiskScore:            res.RiskScore,
		ImpactScore:          float64(ap.TotalScore),
		Toxic:                fin.ToxicMultiplier,
		GlobalImage:          fin.GlobalImageScore,
		RBAC:                 ap.RBACScore,
		Network:              ap.NetworkScore,
		Mount:                ap.MountScore,
		HostNetwork:          ap.MountDetails.HostNetwork,
		HostPID:              ap.MountDetails.HostPID,
		NetworkIsolationNone: ap.NetworkDetails.Isolation == scoring.NetworkIsolationNone,
		SAName:               ap.RBACDetails.ServiceAccount,
	}

	// 노출 (risk 축)
	if s.exposure != nil {
		if ex, eerr := s.exposure.GetByPodUID(ctx, cluster, podUID); eerr == nil && ex != nil && ex.Exposed {
			in.Exposed = true
			in.ExposedVia = exposedViaLabel(ex)
		}
	}

	// privileged 컨테이너 / hostPath 볼륨 실제 이름 (mount 항목 id용)
	if spec, serr := s.attackPath.GetPodSpecByUID(ctx, cluster, podUID); serr == nil && spec != nil {
		in.PrivilegedContainers = privilegedContainerNames(spec.Containers)
		in.HostPathVolumes = hostPathVolumeNames(spec.Volumes)
	}

	// SA 최종 권한 전체 → PermItem (rbac 항목용). SA namespace = pod namespace.
	if s.rbacChain != nil && in.SAName != "" {
		if perms, perr := s.rbacChain.ListSAPermissions(ctx, cluster, ap.PodNamespace, in.SAName); perr == nil {
			for _, p := range perms {
				pi := scoring.PermItem{Verb: p.Verb, Resource: p.Resource, Severity: permSeverity(p.Verb, p.Resource)}
				if p.Namespace != nil {
					pi.Namespace = *p.Namespace
				}
				in.AllPerms = append(in.AllPerms, pi)
			}
		}
	}

	// 이미지 CVE 목록 + 점수 (cve 항목용).
	// 점수는 GetByCVEID로 보강(현재 N+1). 대용량 이미지면 ANY($1) 배치 쿼리로 최적화 권장.
	if s.globalRepo != nil && fin.UsedImageDigest != "" {
		if rows, cerr := s.globalRepo.ListCVEsByImageDigest(ctx, fin.UsedImageDigest); cerr == nil {
			for _, row := range rows {
				if row.CVEID == "" {
					continue
				}
				score := 0.0
				if g, gerr := s.globalRepo.GetByCVEID(ctx, row.CVEID); gerr == nil && g != nil {
					score = g.GlobalScore
				}
				in.CVEs = append(in.CVEs, scoring.CVEItem{
					ID: row.CVEID, Score: score, Severity: strings.ToLower(row.Severity), Fixed: row.FixedVersion,
					Package: row.PkgName,
				})
			}
		}
	}

	set := scoring.BuildRemediationItems(in)

	// ── ISMS-P 가산 차감 부착 ──
	// ISMS-P 미준수 가산(상3/중2/하1)은 Final에 더해진다(grc_risk_score.go). 보완이 그 근본원인을
	// 없애면 룰이 해소돼 가산분이 빠진다 → 보완 항목/그룹에 isms_reduction(axis=risk)을 붙인다.
	// 기존 점수/reduction 코어는 불변. companyID/grc 없으면 조용히 생략.
	s.attachISMSReductions(ctx, companyID, cluster, ap.PodNamespace, ap.PodName, in.SAName, res, &set)

	res.RemediationItems = set.Items
	res.RemediationGroups = set.Groups

	// ── 공격 시나리오 3분류 뷰(categories) — 같은 신호 재사용 + 양방향 blast 엣지 ──
	// CVE/권한/NetworkPolicy. 권한·NetworkPolicy는 이 pod이 src/dst인 엣지를 모두 본다.
	s.buildCategories(ctx, cluster, podUID, ap.PodNamespace, ap.NetworkDetails.Isolation, in, res)
}

// buildCategories — 이미 모은 신호(in) + 격리등급에 양방향 blast 엣지를 더해 3분류 뷰를 만든다.
// 점수/리듀스와 무관한 표시용 구조화 출력(res.Categories).
//
// rbac 엣지에는 그 엣지를 만든 "출발 SA의 실제 초기권한"을 붙인다(권한 항목이 "…권한을 해제하세요"로
// 구체 지목하도록). 출발 SA = src 엣지는 이 pod의 SA, dst 엣지는 상대(출발) pod의 SA(uid→SA 조회).
// rbac_sa_initial_permissions를 SA당 1회만 조회하도록 캐시한다.
func (s *ScenarioService) buildCategories(ctx context.Context, cluster, podUID, podNamespace, isolation string, in scoring.RemediationInput, res *scoring.PodScenarioResult) {
	catIn := scoring.CategoriesInput{
		CVEs:                 in.CVEs,
		SAName:               in.SAName,
		PrivilegedContainers: in.PrivilegedContainers,
		HostPathVolumes:      in.HostPathVolumes,
		HostNetwork:          in.HostNetwork,
		HostPID:              in.HostPID,
		NetworkIsolation:     isolation,
	}
	// node-level RBAC: 최종권한(흡수 후, rbac_sa_permissions) 대신 "원래(흡수 전) 권한 +
	// 권한상승 인과"를 채운다. 흡수로 생긴 권한은 회수 대상이 아니라 "상승 결과"이므로,
	// 트리거가 된 원래 권한만 회수 지목하고, 그로 인한 상승 권한은 인과로 같이 보여준다.
	if s.rbacChain != nil && in.SAName != "" {
		catIn.InitialPerms = s.saInitialPerms(ctx, cluster, podNamespace, in.SAName)
		catIn.Escalations = s.rbacEscalations(ctx, cluster, podNamespace, in.SAName)
	}
	if s.blastRepo != nil {
		// SA(ns/name)당 측면이동 초기권한 캐시 — 같은 SA 중복 조회 방지.
		lateralCache := map[string][]string{}
		lateralFor := func(ns, saName string) []string {
			if ns == "" || saName == "" {
				return nil
			}
			key := ns + "/" + saName
			if v, ok := lateralCache[key]; ok {
				return v
			}
			v := s.lateralInitialPerms(ctx, cluster, ns, saName)
			lateralCache[key] = v
			return v
		}
		// 출발 pod uid → (saNamespace, saName) 캐시 — dst 엣지용.
		saCache := map[string][2]string{}
		saForPod := func(uid string) (string, string) {
			if uid == "" {
				return "", ""
			}
			if v, ok := saCache[uid]; ok {
				return v[0], v[1]
			}
			ns, name, err := s.blastRepo.GetPodSA(ctx, cluster, uid)
			if err != nil {
				ns, name = "", ""
			}
			saCache[uid] = [2]string{ns, name}
			return ns, name
		}

		if oe, err := s.blastRepo.GetOutgoingBySource(ctx, cluster, podUID); err == nil {
			for _, e := range oe {
				// 출발 = 이 pod → 출발 SA = 이 pod의 SA(in.SAName), ns = 이 pod namespace.
				catIn.OutEdges = append(catIn.OutEdges, scoring.CatEdge{
					Peer: e.TargetName, PeerUID: e.TargetPodUID, Namespace: e.TargetNamespace, WinChannel: e.WinChannel,
					Reason: e.Reason, PHost: e.PHost, PRBAC: e.PRBAC, PNet: e.PNet,
					SrcSA: in.SAName, LateralPerms: lateralFor(podNamespace, in.SAName),
				})
			}
		}
		if ie, err := s.blastRepo.GetIncomingByTarget(ctx, cluster, podUID); err == nil {
			for _, e := range ie {
				// 출발 = 상대 pod → 출발 SA = 상대 pod의 SA(uid로 조회).
				saNS, saName := saForPod(e.SourcePodUID)
				if saNS == "" {
					saNS = e.SourceNamespace
				}
				catIn.InEdges = append(catIn.InEdges, scoring.CatEdge{
					Peer: e.SourceName, PeerUID: e.SourcePodUID, Namespace: e.SourceNamespace, WinChannel: e.WinChannel,
					Reason: e.Reason, PHost: e.PHost, PRBAC: e.PRBAC, PNet: e.PNet,
					SrcSA: saName, LateralPerms: lateralFor(saNS, saName),
				})
			}
		}
	}
	cats := scoring.BuildCategories(catIn)
	res.Categories = &cats
}

// lateralInitialPerms — SA의 흡수 전(initial) 권한 중 측면이동 verb(exec/attach/ephemeral·
// pods/portforward·nodes/proxy·core 와일드카드)만 "verb resource"로 추려 반환(중복 제거).
// rbac_sa_initial_permissions를 읽어, 엣지 생성과 같은 기준(blastedge.IsLateralMovement)으로 필터한다.
// 조회 실패·해당 권한 없음이면 nil → edgePriv가 reason/일반 문구로 폴백한다.
func (s *ScenarioService) lateralInitialPerms(ctx context.Context, cluster, ns, saName string) []string {
	if s.rbacChain == nil {
		return nil
	}
	perms, err := s.rbacChain.ListSAInitialPermissions(ctx, cluster, ns, saName)
	if err != nil || len(perms) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range perms {
		if !blastedge.IsLateralMovement(blastedge.Perm{
			APIGroup: p.APIGroup, Resource: p.Resource, Verb: p.Verb,
			Namespace: p.Namespace, ResourceName: p.ResourceName,
		}) {
			continue
		}
		label := p.Verb + " " + p.Resource
		if !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	return out
}

// saInitialPerms — SA의 "원래(흡수 전)" 직접 보유 권한 전체를 PermItem으로 반환.
// node-level 회수 후보의 출처 — 최종권한(rbac_sa_permissions)이 아니라 흡수 전 직접권한
// (rbac_sa_initial_permissions). 흡수로 생긴 권한을 회수 대상에서 빼기 위함.
func (s *ScenarioService) saInitialPerms(ctx context.Context, cluster, ns, saName string) []scoring.PermItem {
	if s.rbacChain == nil {
		return nil
	}
	perms, err := s.rbacChain.ListSAInitialPermissions(ctx, cluster, ns, saName)
	if err != nil {
		return nil
	}
	out := make([]scoring.PermItem, 0, len(perms))
	for _, p := range perms {
		pi := scoring.PermItem{Verb: p.Verb, Resource: p.Resource, Severity: permSeverity(p.Verb, p.Resource)}
		if p.Namespace != nil {
			pi.Namespace = *p.Namespace
		}
		out = append(out, pi)
	}
	return out
}

// rbacEscalations — 이 SA의 권한상승 인과(룰별 트리거→흡수)를 모은다.
// transition_triggers(어떤 "원래" 권한이 룰을 트리거했나) + rbac_escalation_paths(그래서
// 흡수한 권한)를 via_transition(룰 ID)으로 묶는다. 데이터 없으면 nil(폴백: 인과 카드 생략).
func (s *ScenarioService) rbacEscalations(ctx context.Context, cluster, ns, saName string) []scoring.RBACEscalation {
	if s.rbacChain == nil {
		return nil
	}
	detail, err := s.rbacChain.GetSA(ctx, cluster, ns, saName)
	if err != nil || detail == nil {
		return nil
	}
	// transition_triggers JSONB: [{transition, triggered_by:[{...perm}]}]
	var triggers []struct {
		Transition  string           `json:"transition"`
		TriggeredBy []map[string]any `json:"triggered_by"`
	}
	if len(detail.Report.TransitionTriggers) > 0 {
		if uerr := json.Unmarshal(detail.Report.TransitionTriggers, &triggers); uerr != nil {
			return nil
		}
	}
	if len(triggers) == 0 {
		return nil
	}
	// 룰 ID → 흡수(상승) 권한 "verb resource" 목록(중복 제거).
	escByRule := map[string][]string{}
	escSeen := map[string]map[string]bool{}
	for _, e := range detail.Escalation {
		label := strings.TrimSpace(e.Verb + " " + e.Resource)
		if label == "" {
			continue
		}
		if escSeen[e.ViaTransition] == nil {
			escSeen[e.ViaTransition] = map[string]bool{}
		}
		if escSeen[e.ViaTransition][label] {
			continue
		}
		escSeen[e.ViaTransition][label] = true
		escByRule[e.ViaTransition] = append(escByRule[e.ViaTransition], label)
	}
	out := make([]scoring.RBACEscalation, 0, len(triggers))
	for _, t := range triggers {
		var trig []string
		seen := map[string]bool{}
		for _, p := range t.TriggeredBy {
			verb, _ := p["verb"].(string)
			res, _ := p["resource"].(string)
			label := strings.TrimSpace(verb + " " + res)
			if label == "" || seen[label] {
				continue
			}
			seen[label] = true
			trig = append(trig, label)
		}
		out = append(out, scoring.RBACEscalation{
			Rule:           t.Transition,
			TriggerPerms:   trig,
			EscalatedPerms: escByRule[t.Transition],
		})
	}
	return out
}

// attachISMSReductions — GRC에서 이 pod의 ISMS-P 미준수 가산 breakdown을 받아,
// 점수 가산된 룰을 보완 버킷에 매핑해 가산 차감(scoring.AttachISMSReductions)을 부착한다.
func (s *ScenarioService) attachISMSReductions(ctx context.Context, companyID, cluster, namespace, podName, saName string, res *scoring.PodScenarioResult, set *scoring.RemediationSet) {
	if s.grc == nil || companyID == "" || namespace == "" || podName == "" {
		return
	}
	bd := s.grc.ComputePodISMSPAddend(ctx, companyID, cluster, namespace, podName)
	if bd == nil || bd.Addend <= 0 || len(bd.Rules) == 0 {
		return
	}
	fired := make([]scoring.ISMSRuleHit, 0, len(bd.Rules))
	for _, r := range bd.Rules {
		fired = append(fired, scoring.ISMSRuleHit{RuleID: r.RuleID, Severity: r.Severity, Weight: r.Weight})
	}
	scoring.AttachISMSReductions(set, fired, saName, bd.Addend, res.RiskScore)
	res.ISMSAddend = bd.Addend
	res.ISMSRules = fired
}

// permSeverity — 표시·정렬용 등급(딥리서치 합의 기반). 점수 계산과는 무관(라벨).
func permSeverity(verb, resource string) string {
	switch {
	case verb == "*" || resource == "*":
		return "critical"
	case verb == "impersonate":
		return "critical"
	case (resource == "rolebindings" || resource == "clusterrolebindings") && (verb == "create" || verb == "bind"):
		return "critical"
	case (resource == "roles" || resource == "clusterroles") && (verb == "bind" || verb == "escalate"):
		return "critical"
	case resource == "serviceaccounts/token" && verb == "create":
		return "critical"
	case resource == "certificatesigningrequests" && (verb == "create" || verb == "approve"):
		return "critical"
	case resource == "secrets" && (verb == "get" || verb == "list" || verb == "watch"):
		return "high"
	case (resource == "pods/exec" || resource == "pods/attach") && verb == "create":
		return "high"
	case resource == "pods" && verb == "create":
		return "high"
	case resource == "nodes/proxy":
		return "high"
	}
	return "medium"
}
