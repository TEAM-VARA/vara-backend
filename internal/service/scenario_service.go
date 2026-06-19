package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ScenarioService — 기존 신호(attack-path/rbac/exposure/vuln)를 모아
// 공격 시나리오 줄글 + 보완대책 줄글(scoring.PodScenarioResult)을 생성한다.
//
// 신규 수집은 하지 않는다. 이미 계산된 결과를 ATT&CK technique으로 "라벨링"만 한다.
type ScenarioService struct {
	attackPath *AttackPathService          // coarse RBAC/NET/MOUNT 신호 + pod spec(실제 컨테이너/볼륨 이름)
	finalScore *FinalScoringService        // RiskScore/RiskLevel + UsedTopCVE (pod별 대표 CVE)
	globalRepo *postgres.GlobalScoringRepo // CVE → CVSS 벡터·점수·KEV
	blastRepo  *postgres.BlastEdgesRepo    // outgoing(전파) 엣지: win_channel·reason·실제 타겟
	exposure   *ExposureService            // Exposed/ExposedVia (LoadBalancer/NodePort/Ingress)
	rbacChain  *RBACChainService           // 정밀 verb·resource (create workload / write webhook / delete events)
}

// NewScenarioService — attack-path + final-score + global(CVE) + blast(전파 엣지)
// + exposure(노출) + rbacchain(정밀 권한) 의존성으로 생성.
func NewScenarioService(
	ap *AttackPathService,
	fs *FinalScoringService,
	gr *postgres.GlobalScoringRepo,
	br *postgres.BlastEdgesRepo,
	ex *ExposureService,
	rc *RBACChainService,
) *ScenarioService {
	return &ScenarioService{
		attackPath: ap, finalScore: fs, globalRepo: gr, blastRepo: br,
		exposure: ex, rbacChain: rc,
	}
}

// BuildForPod — pod 1개의 시나리오/보완 줄글 생성.
func (s *ScenarioService) BuildForPod(ctx context.Context, cluster, podUID string) (*scoring.PodScenarioResult, error) {
	in := scoring.ScenarioInput{
		ClusterName:   cluster,
		PodUID:        podUID,
		IRSACollected: false, // SA annotations 미수집 (DB 실측) → 9020 제외 고지
	}

	// ── attack_path_scores 에서 MOUNT / NET / RBAC(coarse) 직접 매핑 ──
	ap, err := s.attackPath.GetByPodUID(ctx, cluster, podUID)
	if err != nil {
		return nil, err
	}
	if ap != nil {
		in.PodName = ap.PodName
		in.Namespace = ap.PodNamespace
		in.ServiceAccount = ap.RBACDetails.ServiceAccount

		// MOUNT (이름은 cluster_pods 에서 보강 권장 — 여기선 대표 표기)
		if ap.MountDetails.HasPrivileged {
			in.PrivilegedContainers = []string{"privileged 컨테이너"}
		}
		if ap.MountDetails.HasHostPath {
			in.HostPathVolumes = []string{"hostPath 볼륨"}
		}
		in.HostNetwork = ap.MountDetails.HostNetwork
		in.HostPID = ap.MountDetails.HostPID

		// NET
		in.NetworkIsolation = ap.NetworkDetails.Isolation

		// RBAC (coarse: attack_path level 신호. 정밀은 rbacchain 권장)
		in.CanListSecrets = ap.RBACDetails.HasSecretsAccess
		in.CanExec = ap.RBACDetails.HasPodExec
		in.IsClusterAdmin = ap.RBACDetails.IsClusterAdmin
		in.CanBindClusterAdmin = ap.RBACDetails.HasWildcard // 근사 — rbacchain의 bind/escalate로 교체 권장
	}

	// ── final_scores: RiskScore/RiskLevel + pod 대표 CVE(UsedTopCVE) ──
	// best-effort: final 결과/CVE 조회 실패는 시나리오 생성을 막지 않는다.
	if s.finalScore != nil {
		if fin, ferr := s.finalScore.GetByPodUID(ctx, cluster, podUID); ferr == nil && fin != nil {
			in.RiskScore = fin.FinalScore
			in.RiskLevel = fin.RiskLevel
			s.enrichCVE(ctx, &in, fin.UsedTopCVE)
		}
	}

	// ── blast_edges: outgoing(전파) 엣지 — win_channel·reason·실제 타겟 ──
	// 채워지면 BuildPodScenario가 outgoing 섹션을 휴리스틱 대신 이 엣지로 구성한다.
	// best-effort: 조회 실패는 시나리오 생성을 막지 않는다(휴리스틱 폴백).
	if s.blastRepo != nil {
		if be, berr := s.blastRepo.GetOutgoingBySource(ctx, cluster, podUID); berr == nil {
			for _, e := range be {
				in.ReachEdges = append(in.ReachEdges, scoring.BlastEdge{
					Channel:    e.WinChannel,
					Reason:     e.Reason,
					TargetName: e.TargetName,
					RBACProb:   e.PRBAC,
				})
			}
		}
	}

	// ── exposure_scores: 외부 노출 여부·경로(in.Exposed/in.ExposedVia) ──
	// best-effort: 조회 실패/미계산은 incoming(9005) 생략으로 처리.
	if s.exposure != nil {
		if ex, eerr := s.exposure.GetByPodUID(ctx, cluster, podUID); eerr == nil && ex != nil {
			in.Exposed = ex.Exposed
			if ex.Exposed {
				in.ExposedVia = exposedViaLabel(ex)
			}
		}
	}

	// ── cluster_pods: privileged 컨테이너·hostPath 볼륨 실제 이름 ──
	// spec을 찾으면 위 attack_path의 대표 표기("privileged 컨테이너")를 실제 이름으로 교체한다.
	if spec, serr := s.attackPath.GetPodSpecByUID(ctx, cluster, podUID); serr == nil && spec != nil {
		if names := privilegedContainerNames(spec.Containers); len(names) > 0 {
			in.PrivilegedContainers = names
		}
		if names := hostPathVolumeNames(spec.Volumes); len(names) > 0 {
			in.HostPathVolumes = names
		}
	}

	// ── rbacchain perms: 정밀 verb·resource(create workload / write webhook / delete events) ──
	// attack_path는 coarse 신호(secrets/exec/cluster-admin)만 주므로, 나머지 3개는 SA 최종 권한에서 도출.
	if s.rbacChain != nil && in.ServiceAccount != "" {
		if perms, perr := s.rbacChain.ListSAPermissions(ctx, cluster, in.Namespace, in.ServiceAccount); perr == nil {
			ev := deriveRBACFlags(perms)
			in.CanCreateWorkload = ev.canCreateWorkload
			in.CanWriteWebhook = ev.canWriteWebhook
			in.CanDeleteEvents = ev.canDeleteEvents
			in.CreateWorkloadPerms = joinPermsCap(ev.workloadPerms, 3)
			in.WriteWebhookPerms = joinPermsCap(ev.webhookPerms, 3)
			in.DeleteEventsPerms = joinPermsCap(ev.eventsPerms, 3)
			// exec은 attack_path(coarse)보다 정밀 — rbacchain이 잡으면 켜고 근거 권한을 부기.
			// (nodes/proxy 등 attack_path가 놓치는 측면이동 권한까지 포착)
			in.CanExec = in.CanExec || ev.canExec
			in.ExecPerms = joinPermsCap(ev.execPerms, 3)
		}
	}

	res := scoring.BuildPodScenario(in)
	return &res, nil
}

// enrichCVE — pod 대표 CVE(global_scores)에서 CVSS 벡터·점수·KEV를 읽어
// ScenarioInput 의 VULN 필드를 채운다. cveID 가 비었거나 조회 실패면 조용히 패스.
func (s *ScenarioService) enrichCVE(ctx context.Context, in *scoring.ScenarioInput, cveID string) {
	if cveID == "" || s.globalRepo == nil {
		return
	}
	g, err := s.globalRepo.GetByCVEID(ctx, cveID)
	if err != nil || g == nil {
		return
	}
	in.TopCVE = cveID
	in.CVEScore = g.CVSSScore
	in.CVEKEV = g.InKEV
	in.CVERemote, in.CVEAvailabilityImpact, in.CVEConfidentialityImpact, in.CVEScopeChanged =
		parseCVSSVector(g.CVSSVector)
}

// parseCVSSVector — CVSS v3.1/v4.0 벡터 문자열에서 시나리오 판정에 쓰는 플래그 추출.
//
//	remote(AV:N) / availability(A:H|VA:H) / confidentiality(C:H|VC:H) / scopeChanged(S:C 또는 v4.0 후속시스템 영향)
//
// "/" 로 토큰 분리 후 키:값 정확 매칭 → "AC:H"가 "C:H"로 오인되는 substring 버그 방지.
func parseCVSSVector(vec string) (remote, availability, confidentiality, scopeChanged bool) {
	m := make(map[string]string)
	for _, tok := range strings.Split(vec, "/") {
		if kv := strings.SplitN(tok, ":", 2); len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	remote = m["AV"] == "N"
	availability = m["A"] == "H" || m["VA"] == "H"
	confidentiality = m["C"] == "H" || m["VC"] == "H"
	scopeChanged = m["S"] == "C" || m["SC"] == "H" || m["SI"] == "H" || m["SA"] == "H"
	return
}

// exposedViaLabel — exposure 결과에서 가장 강한 외부 경로 1개를 사람이 읽는 라벨로 만든다.
// 줄글에 "이 Pod이 %s 상태라"로 끼워지므로 "…로 외부 노출된" 형태로 끝낸다.
// 우선순위: 외부 노출 Service(LoadBalancer/NodePort) > Ingress(host).
func exposedViaLabel(ex *scoring.ExposureResult) string {
	for _, svc := range ex.MatchedServices {
		if svc.ExternallyExposed {
			return fmt.Sprintf("Service(%s)로 외부 노출된", svc.Type)
		}
	}
	for _, ig := range ex.MatchedIngresses {
		if ig.Host != "" {
			return fmt.Sprintf("Ingress(%s)로 외부 노출된", ig.Host)
		}
		return "Ingress로 외부 노출된"
	}
	return "외부에 노출된"
}

// privilegedContainerNames — privileged=true 컨테이너의 실제 이름만 추린다.
func privilegedContainerNames(cs []postgres.ContainerInfo) []string {
	var out []string
	for _, c := range cs {
		if c.Privileged && c.Name != "" {
			out = append(out, c.Name)
		}
	}
	return out
}

// hostPathVolumeNames — type=hostPath 볼륨의 실제 이름만 추린다.
func hostPathVolumeNames(vs []postgres.VolumeInfo) []string {
	var out []string
	for _, v := range vs {
		if v.Type == "hostPath" && v.Name != "" {
			out = append(out, v.Name)
		}
	}
	return out
}

// 워크로드 생성으로 간주하는 자원(공격자가 새 컨테이너를 띄울 수 있는 표면).
var workloadCreateResources = map[string]bool{
	"deployments": true, "daemonsets": true, "statefulsets": true,
	"replicasets": true, "replicationcontrollers": true,
	"jobs": true, "cronjobs": true, "pods": true,
}

// admission 웹훅 자원(가짜 검문 웹훅 심기).
var webhookResources = map[string]bool{
	"validatingwebhookconfigurations": true,
	"mutatingwebhookconfigurations":   true,
}

// rbacEvidence — capability별 플래그 + 그 판정의 근거가 된 실제 verb/resource(중복 제거).
// 근거는 finding의 caveat에 부기되어 심사 증적성을 높인다.
type rbacEvidence struct {
	canCreateWorkload, canWriteWebhook, canDeleteEvents, canExec bool
	workloadPerms, webhookPerms, eventsPerms, execPerms          []string
}

// lateralMoveResources — 다른 컨테이너로 들어가 명령 실행(측면이동, 9006)이 가능한 자원.
// nodes/proxy는 kubelet API로 exec 가능. portforward는 포트 접근(9034)이라 제외.
var lateralMoveResources = map[string]bool{
	"pods/exec":                true,
	"pods/attach":              true,
	"pods/ephemeralcontainers": true,
	"nodes/proxy":              true,
}

// deriveRBACFlags — SA 최종 권한 집합에서 시나리오용 정밀 플래그 3개 + 근거 권한을 도출한다.
// verb "*" / resource "*" 와일드카드는 해당 카테고리를 모두 충족시킨다.
func deriveRBACFlags(perms []postgres.PermissionOut) rbacEvidence {
	writeVerbs := map[string]bool{"create": true, "update": true, "patch": true}
	var ev rbacEvidence
	wlSeen, whSeen, evSeen, exSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	addOnce := func(seen map[string]bool, list *[]string, repr string) {
		if !seen[repr] {
			seen[repr] = true
			*list = append(*list, repr)
		}
	}
	for _, p := range perms {
		verbAll := p.Verb == "*"
		resAll := p.Resource == "*"
		repr := permRepr(p)
		if (p.Verb == "create" || verbAll) && (resAll || workloadCreateResources[p.Resource]) {
			ev.canCreateWorkload = true
			addOnce(wlSeen, &ev.workloadPerms, repr)
		}
		if (writeVerbs[p.Verb] || verbAll) && (resAll || webhookResources[p.Resource]) {
			ev.canWriteWebhook = true
			addOnce(whSeen, &ev.webhookPerms, repr)
		}
		if (p.Verb == "delete" || verbAll) && (resAll || p.Resource == "events") {
			ev.canDeleteEvents = true
			addOnce(evSeen, &ev.eventsPerms, repr)
		}
		// exec/attach/ephemeral/nodes-proxy(또는 wildcard) → 측면이동(9006) 근거.
		if resAll || lateralMoveResources[p.Resource] {
			ev.canExec = true
			addOnce(exSeen, &ev.execPerms, repr)
		}
	}
	return ev
}

// permRepr — 권한 1건을 "verb resource" 형태로. core 외 apiGroup은 "verb resource.group"으로 구분.
func permRepr(p postgres.PermissionOut) string {
	if p.APIGroup != "" && p.APIGroup != "*" {
		return fmt.Sprintf("%s %s.%s", p.Verb, p.Resource, p.APIGroup)
	}
	return fmt.Sprintf("%s %s", p.Verb, p.Resource)
}

// joinPermsCap — 근거 권한 목록을 caveat 문구로. 최대 limit개 노출 + 초과 시 "외 N개".
func joinPermsCap(perms []string, limit int) string {
	if len(perms) == 0 {
		return ""
	}
	if len(perms) <= limit {
		return strings.Join(perms, ", ")
	}
	return fmt.Sprintf("%s 외 %d개", strings.Join(perms[:limit], ", "), len(perms)-limit)
}
