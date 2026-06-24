package service

import (
	"context"
	"strings"

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
	s.buildCategories(ctx, cluster, podUID, ap.NetworkDetails.Isolation, in, res)
}

// buildCategories — 이미 모은 신호(in) + 격리등급에 양방향 blast 엣지를 더해 3분류 뷰를 만든다.
// 점수/리듀스와 무관한 표시용 구조화 출력(res.Categories). refetch는 엣지 2건뿐.
func (s *ScenarioService) buildCategories(ctx context.Context, cluster, podUID, isolation string, in scoring.RemediationInput, res *scoring.PodScenarioResult) {
	catIn := scoring.CategoriesInput{
		CVEs:                 in.CVEs,
		SAName:               in.SAName,
		AllPerms:             in.AllPerms,
		PrivilegedContainers: in.PrivilegedContainers,
		HostPathVolumes:      in.HostPathVolumes,
		HostNetwork:          in.HostNetwork,
		HostPID:              in.HostPID,
		NetworkIsolation:     isolation,
	}
	if s.blastRepo != nil {
		if oe, err := s.blastRepo.GetOutgoingBySource(ctx, cluster, podUID); err == nil {
			for _, e := range oe {
				catIn.OutEdges = append(catIn.OutEdges, scoring.CatEdge{
					Peer: e.TargetName, Namespace: e.TargetNamespace, WinChannel: e.WinChannel,
					Reason: e.Reason, PHost: e.PHost, PRBAC: e.PRBAC, PNet: e.PNet,
				})
			}
		}
		if ie, err := s.blastRepo.GetIncomingByTarget(ctx, cluster, podUID); err == nil {
			for _, e := range ie {
				catIn.InEdges = append(catIn.InEdges, scoring.CatEdge{
					Peer: e.SourceName, Namespace: e.SourceNamespace, WinChannel: e.WinChannel,
					Reason: e.Reason, PHost: e.PHost, PRBAC: e.PRBAC, PNet: e.PNet,
				})
			}
		}
	}
	cats := scoring.BuildCategories(catIn)
	res.Categories = &cats
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
