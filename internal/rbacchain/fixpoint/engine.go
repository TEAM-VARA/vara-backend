// engine.go — Python fixpoint/engine.py 1:1.
package fixpoint

import (
	"strings"

	"github.com/vara/backend/internal/rbacchain/snapshot"
)

// PermProvMap — SA 안의 (Permission → []prov) 매핑.
type PermProvMap map[Permission][]map[string]any

// ProvenanceIndex — SA → (Permission → []prov).
type ProvenanceIndex map[snapshot.SAKey]PermProvMap

// InitialPermsFromDP — Python initial_perms_from_dp() 1:1.
//
// dpResult: direct_perm.Extract() 결과 (또는 그 JSON 을 unmarshal한 map).
// dpResult["sa_permissions"] 가 map[string]any 이고 각 value 가 []any 가정.
func InitialPermsFromDP(dpResult map[string]any) map[snapshot.SAKey]*PermissionSet {
	out := map[snapshot.SAKey]*PermissionSet{}
	saPerms, _ := dpResult["sa_permissions"].(map[string]any)
	for saKeyStr, perms := range saPerms {
		ns, name, ok := splitSAKey(saKeyStr)
		if !ok {
			continue
		}
		ps := NewPermissionSet()
		lst, _ := perms.([]any)
		for _, e := range lst {
			pd, _ := e.(map[string]any)
			if pd == nil {
				continue
			}
			ps.Add(snapshot.PermissionFromDict(pd))
		}
		out[snapshot.SAKey{Namespace: ns, Name: name}] = ps
	}
	return out
}

// InitialProvenanceFromDP — Python initial_provenance_from_dp() 1:1.
func InitialProvenanceFromDP(dpResult map[string]any) ProvenanceIndex {
	out := ProvenanceIndex{}
	saPerms, _ := dpResult["sa_permissions"].(map[string]any)
	for saKeyStr, perms := range saPerms {
		ns, name, ok := splitSAKey(saKeyStr)
		if !ok {
			continue
		}
		sa := snapshot.SAKey{Namespace: ns, Name: name}
		lst, _ := perms.([]any)
		for _, e := range lst {
			pd, _ := e.(map[string]any)
			if pd == nil {
				continue
			}
			perm := snapshot.PermissionFromDict(pd)
			directProvs := []map[string]any{}
			if pv, ok := pd["provenance"].([]any); ok {
				for _, pe := range pv {
					if pm, ok := pe.(map[string]any); ok {
						directProvs = append(directProvs, pm)
					}
				}
			}
			if out[sa] == nil {
				out[sa] = PermProvMap{}
			}
			out[sa][perm] = append(out[sa][perm], directProvs...)
		}
	}
	return out
}

func splitSAKey(s string) (string, string, bool) {
	idx := strings.Index(s, "/")
	if idx < 0 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// RunFixpoint — Python run_fixpoint() 1:1.
//
// initialPerms 는 in-place mutate 된다 (Python 과 동일). 호출자는 delta 계산을
// 원하면 SnapshotInitialPerms() 로 사본을 미리 떠야 한다.
//
// transitions 가 nil 이면 activeFlags 로 TransitionsForFlags() 사용.
// initialProvenance 가 nil 이면 빈 인덱스로 시작.
func RunFixpoint(
	initialPerms map[snapshot.SAKey]*PermissionSet,
	snap map[string]any,
	transitions []TransitionFunc,
	activeFlags map[string]struct{},
	initialProvenance ProvenanceIndex,
) (map[snapshot.SAKey]*PermissionSet, ProvenanceIndex, error) {

	if transitions == nil {
		if activeFlags == nil {
			activeFlags = map[string]struct{}{}
		}
		transitions = TransitionsForFlags(activeFlags)
	}

	allPerms := initialPerms

	provenance := initialProvenance
	if provenance == nil {
		provenance = ProvenanceIndex{}
	}

	// 초기 worklist: 모든 (sa, perm) 쌍.
	// SA 순회를 sorted 로 강제해 worklist 처리 순서를 결정적으로 만든다.
	// Go map iteration 이 random 인 점이 cluster-admin short-circuit 과 결합하면
	// 실행마다 다른 영수증 (via_transitions) 이 나오는 재현성 문제가 생긴다.
	// 의미적 fixpoint (cluster-admin 도달 SA 등) 는 단조 증가 보장으로 동일하지만,
	// "어느 룰로 도달했나" 보고는 worklist 순서에 따라 달라진다. 그래서 결정화.
	type workItem struct {
		SA   snapshot.SAKey
		Perm Permission
	}
	var worklist []workItem
	for _, sa := range sortedSAKeys(allPerms) {
		ps := allPerms[sa]
		for _, perm := range ps.Iter() {
			worklist = append(worklist, workItem{sa, perm})
		}
	}

	for len(worklist) > 0 {
		// pop (LIFO — Python list.pop() 등가)
		n := len(worklist) - 1
		item := worklist[n]
		worklist = worklist[:n]

		sa := item.SA
		if _, ok := allPerms[sa]; !ok {
			continue
		}

		// cluster-admin short-circuit (Python 동일)
		if SAHasClusterAdmin(sa, allPerms) {
			continue
		}

		for _, transition := range transitions {
			err := transition(sa, allPerms, snap, func(targetSA snapshot.SAKey, newPerm Permission, prov map[string]any) {
				if _, ok := allPerms[targetSA]; !ok {
					allPerms[targetSA] = NewPermissionSet()
				}
				if allPerms[targetSA].Add(newPerm) {
					// 새 권한 → worklist + provenance 누적
					worklist = append(worklist, workItem{targetSA, newPerm})
					if provenance[targetSA] == nil {
						provenance[targetSA] = PermProvMap{}
					}
					provenance[targetSA][newPerm] = append(provenance[targetSA][newPerm], prov)
				}
				// cover된 권한은 prov 누적 skip (Python 2026-05-18 변경 동일)
			})
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return allPerms, provenance, nil
}

// SAHasClusterAdmin — Python sa_has_cluster_admin() 1:1.
func SAHasClusterAdmin(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet) bool {
	ps, ok := allPerms[sa]
	if !ok {
		return false
	}
	return ps.Contains(ClusterAdmin)
}

// ClusterAdminSAs — Python cluster_admin_sas() 1:1.
func ClusterAdminSAs(allPerms map[snapshot.SAKey]*PermissionSet) []snapshot.SAKey {
	var out []snapshot.SAKey
	for sa := range allPerms {
		if SAHasClusterAdmin(sa, allPerms) {
			out = append(out, sa)
		}
	}
	return out
}
