package service

import (
	"context"
	"strings"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ScenarioService — 기존 신호(attack-path/rbac/exposure/vuln)를 모아
// 공격 시나리오 줄글 + 보완대책 줄글(scoring.PodScenarioResult)을 생성한다.
//
// 신규 수집은 하지 않는다. 이미 계산된 결과를 ATT&CK technique으로 "라벨링"만 한다.
type ScenarioService struct {
	attackPath *AttackPathService
	finalScore *FinalScoringService        // RiskScore/RiskLevel + UsedTopCVE (pod별 대표 CVE)
	globalRepo *postgres.GlobalScoringRepo // CVE → CVSS 벡터·점수·KEV
	// 권장 주입 (정밀화):
	//   rbacChain  *RBACChainService   // 정밀 verb·resource (create workload/webhook/delete events/bind)
	//   exposure   *ExposureService    // Exposed/ExposedVia
	//   clusterRepo *postgres.ClusterReaderRepo // privileged 컨테이너명·hostPath 볼륨명
}

// NewScenarioService — attack-path + final-score + global(CVE) 의존성으로 생성.
func NewScenarioService(ap *AttackPathService, fs *FinalScoringService, gr *postgres.GlobalScoringRepo) *ScenarioService {
	return &ScenarioService{attackPath: ap, finalScore: fs, globalRepo: gr}
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

	// ── TODO: 단계적 정밀화 (각 소스 주입 후 채움) ──
	//   exposure_scores      → in.Exposed, in.ExposedVia
	//   rbacchain perms      → in.CanCreateWorkload, in.CanWriteWebhook, in.CanDeleteEvents
	//   edges(network)       → in.ReachablePods
	//   cluster_pods         → privileged 컨테이너 실제 이름, hostPath 볼륨 실제 이름

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
//   remote(AV:N) / availability(A:H|VA:H) / confidentiality(C:H|VC:H) / scopeChanged(S:C 또는 v4.0 후속시스템 영향)
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
