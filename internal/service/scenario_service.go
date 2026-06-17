package service

import (
	"context"

	"github.com/vara/backend/internal/domain/scoring"
)

// ScenarioService — 기존 신호(attack-path/rbac/exposure/vuln)를 모아
// 공격 시나리오 줄글 + 보완대책 줄글(scoring.PodScenarioResult)을 생성한다.
//
// 신규 수집은 하지 않는다. 이미 계산된 결과를 ATT&CK technique으로 "라벨링"만 한다.
type ScenarioService struct {
	attackPath *AttackPathService
	// 권장 주입 (정밀화):
	//   rbacChain  *RBACChainService   // 정밀 verb·resource (create workload/webhook/delete events/bind)
	//   exposure   *ExposureService    // Exposed/ExposedVia
	//   finalScore *FinalScoringService // RiskScore/RiskLevel
	//   vuln       *GlobalScoringService // TopCVE + CVSS + KEV/EPSS
	//   clusterRepo *postgres.ClusterReaderRepo // privileged 컨테이너명·hostPath 볼륨명
}

// NewScenarioService — 최소 의존성(attack-path)으로 생성. 나머지는 단계적으로 주입.
func NewScenarioService(ap *AttackPathService) *ScenarioService {
	return &ScenarioService{attackPath: ap}
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

	// ── TODO: 단계적 정밀화 (각 소스 주입 후 채움) ──
	//   exposure_scores      → in.Exposed, in.ExposedVia
	//   rbacchain perms      → in.CanCreateWorkload, in.CanWriteWebhook, in.CanDeleteEvents
	//   edges(network)       → in.ReachablePods
	//   final_scores         → in.RiskScore, in.RiskLevel
	//   global/sbom+kev+epss → in.TopCVE, in.CVEScore, in.CVEKEV, in.CVERemote,
	//                          in.CVEAvailabilityImpact, in.CVEConfidentialityImpact, in.CVEScopeChanged
	//   cluster_pods         → privileged 컨테이너 실제 이름, hostPath 볼륨 실제 이름

	res := scoring.BuildPodScenario(in)
	return &res, nil
}
