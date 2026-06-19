package grc

import "fmt"

// ── 결함 귀속 스코프 (cluster/account fan-out + 점수 dedup) ──
//
// canonical 평가 1회 → 표시 N개 pod에 투영 → 점수 canonical 단위 1회.
// risk_scope는 결함의 점수 귀속 단위, fanout은 표시 시 영향 pod 투영 범위.
const (
	ScopePod      = "pod"       // pod별 직접 평가 (self)
	ScopePodChain = "pod_chain" // 연관 자산 평가 → 그 자산 쓰는 pod에 귀속
	ScopeCluster  = "cluster"   // 클러스터 1개 단위 (모든 pod에 투영)
	ScopeAccount  = "account"   // AWS 계정/VPC 단위 (계정 내 pod에 투영)
)

const (
	FanoutSelf            = "self"
	FanoutAssetConsumers  = "asset_consumers"
	FanoutAllPodsCluster  = "all_pods_in_cluster"
	FanoutAllPodsAccount  = "all_pods_in_account"
	FanoutNodesPods       = "nodes_pods"
)

// 조치 주체 힌트 (inherited 결함의 책임 그룹 분리용)
const (
	OwnerWorkload     = "workload"      // pod/워크로드 팀
	OwnerClusterAdmin = "cluster-admin" // 클러스터 관리자
	OwnerAccountAdmin = "account-admin" // AWS 계정 관리자
)

// IsInheritedScope reports whether a scope is fanned out from a higher unit
// (cluster/account) and thus displayed on pods but not owned by them.
func IsInheritedScope(scope string) bool {
	return scope == ScopeCluster || scope == ScopeAccount
}

// OwnerHintForScope maps a risk_scope to the responsible owner group.
func OwnerHintForScope(scope string) string {
	switch scope {
	case ScopeCluster:
		return OwnerClusterAdmin
	case ScopeAccount:
		return OwnerAccountAdmin
	default:
		return OwnerWorkload
	}
}

// CanonicalID builds the stable dedup key for a finding. This id is the DISTINCT
// basis for risk aggregation — the same finding projected onto N pods shares one id.
//
//	pod        → pod:<podUID>:<ruleID>
//	pod_chain  → <assetKind>:<assetUID>:<ruleID>   (e.g. sa:<uid>:R-2.5.5-01)
//	cluster    → cluster:<clusterName>:<ruleID>
//	account    → account:<accountID>:<ruleID>  (SG는 sg:<sgID>:<ruleID> — assetKind=sg로 호출)
func CanonicalID(scope, clusterName, accountID, assetKind, assetUID, ruleID string) string {
	switch scope {
	case ScopePodChain:
		return fmt.Sprintf("%s:%s:%s", assetKind, assetUID, ruleID)
	case ScopeCluster:
		return fmt.Sprintf("cluster:%s:%s", clusterName, ruleID)
	case ScopeAccount:
		// SG처럼 자원 단위 식별자가 있으면 그걸로(assetKind:assetUID), 없으면 계정 단위.
		if assetKind != "" && assetUID != "" {
			return fmt.Sprintf("%s:%s:%s", assetKind, assetUID, ruleID)
		}
		return fmt.Sprintf("account:%s:%s", accountID, ruleID)
	default: // ScopePod
		return fmt.Sprintf("pod:%s:%s", assetUID, ruleID)
	}
}
