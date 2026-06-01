// dump.go — Python fixpoint/dump.py 1:1.
package fixpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vara/backend/internal/rbacchain/snapshot"
)

// ----------------------------------------------------------------------------
// 직렬화 helper
// ----------------------------------------------------------------------------

// _perm_repr — Python 한 줄 표기.
func permRepr(p Permission) string {
	if !p.NonResourceURL.IsNull {
		return fmt.Sprintf("nonResourceURL(%s).%s", p.NonResourceURL.Value, p.Verb)
	}
	ag := p.APIGroup
	if ag == "" {
		ag = "core"
	}
	ns := "*"
	if !p.Namespace.IsNull {
		ns = p.Namespace.Value
	}
	rn := ""
	if !p.ResourceName.IsNull && p.ResourceName.Value != "" {
		rn = "[" + p.ResourceName.Value + "]"
	}
	return fmt.Sprintf("%s/%s%s.%s @ ns=%s", ag, p.Resource, rn, p.Verb, ns)
}

func saStr(sa snapshot.SAKey) string { return sa.String() }

func sortedSAKeys(m map[snapshot.SAKey]*PermissionSet) []snapshot.SAKey {
	keys := make([]snapshot.SAKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})
	return keys
}

func sortedSAKeysProv(m ProvenanceIndex) []snapshot.SAKey {
	keys := make([]snapshot.SAKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})
	return keys
}

// ----------------------------------------------------------------------------
// 내부 빌더
// ----------------------------------------------------------------------------

// _build_all_perms — Python _build_all_perms 1:1.
func buildAllPerms(allPerms map[snapshot.SAKey]*PermissionSet) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, sa := range sortedSAKeys(allPerms) {
		ps := allPerms[sa]
		entries := make([]map[string]any, 0, ps.Len())
		for _, p := range ps.Iter() {
			entries = append(entries, permToDict(p))
		}
		out[saStr(sa)] = entries
	}
	return out
}

// _build_provenance — Python _build_provenance 1:1.
func buildProvenance(prov ProvenanceIndex) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, sa := range sortedSAKeysProv(prov) {
		permMap := prov[sa]
		entries := []map[string]any{}
		for perm, provList := range permMap {
			entries = append(entries, map[string]any{
				"permission":      permToDict(perm),
				"permission_repr": permRepr(perm),
				"provenance":      provList,
			})
		}
		out[saStr(sa)] = entries
	}
	return out
}

// _build_delta — Python _build_delta 1:1.
//
// "신규" 정의: initial_perms 에 해당 Permission 객체가 없던 것.
// PermissionSet.Contains 는 covers 기반이지만 Python set 사용은 == 기반 (객체 동일성).
// Go 도 == 기반 set 으로 구현 (frozen dataclass → struct == 등가).
func buildDelta(
	allPerms map[snapshot.SAKey]*PermissionSet,
	initialPerms map[snapshot.SAKey]*PermissionSet,
	provenance ProvenanceIndex,
) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, sa := range sortedSAKeys(allPerms) {
		ps := allPerms[sa]
		initial := initialPerms[sa]
		initialSet := map[Permission]struct{}{}
		if initial != nil {
			for _, p := range initial.Iter() {
				initialSet[p] = struct{}{}
			}
		}
		var newPerms []Permission
		for _, p := range ps.Iter() {
			if _, ok := initialSet[p]; !ok {
				newPerms = append(newPerms, p)
			}
		}
		if len(newPerms) == 0 {
			continue
		}
		entries := []map[string]any{}
		for _, perm := range newPerms {
			provList := []map[string]any{}
			if provenance[sa] != nil {
				provList = provenance[sa][perm]
			}
			var transitionProvs []map[string]any
			transitionSet := map[string]struct{}{}
			for _, pr := range provList {
				if k, _ := pr["kind"].(string); k == "transition" {
					transitionProvs = append(transitionProvs, pr)
					if vt, _ := pr["via_transition"].(string); vt != "" {
						transitionSet[vt] = struct{}{}
					}
				}
			}
			viaTransitions := make([]string, 0, len(transitionSet))
			for vt := range transitionSet {
				viaTransitions = append(viaTransitions, vt)
			}
			sort.Strings(viaTransitions)
			entry := map[string]any{
				"permission":       permToDict(perm),
				"permission_repr":  permRepr(perm),
				"transition_count": len(transitionProvs),
				"via_transitions":  viaTransitions,
				"provenance":       transitionProvs,
			}
			entries = append(entries, entry)
		}
		out[saStr(sa)] = map[string]any{
			"initial_perm_count": len(initialSet),
			"final_perm_count":   ps.Len(),
			"newly_absorbed":     entries,
		}
	}
	return out
}

// _build_delta_md — Python _build_delta_md 1:1.
func buildDeltaMD(
	delta map[string]map[string]any,
	allPerms map[snapshot.SAKey]*PermissionSet,
	initialPerms map[snapshot.SAKey]*PermissionSet,
) string {
	var b strings.Builder
	b.WriteString("# fixpoint delta — SA별 새로 흡수된 권한\n\n")
	fmt.Fprintf(&b, "전체 SA 수: %d  |  변동 SA 수: %d\n\n", len(allPerms), len(delta))

	b.WriteString("## 전체 SA 목록\n\n")
	for _, sa := range sortedSAKeys(allPerms) {
		fmt.Fprintf(&b, "- %s\n", saStr(sa))
	}
	b.WriteString("\n")

	b.WriteString("## 변동 SA 목록\n\n")
	deltaKeys := make([]string, 0, len(delta))
	for k := range delta {
		deltaKeys = append(deltaKeys, k)
	}
	// Python dict 순서를 그대로 따르지 않고 정렬 (Go map iteration 비결정성 회피)
	sort.Strings(deltaKeys)
	if len(deltaKeys) == 0 {
		b.WriteString("- (없음)\n")
	} else {
		for _, k := range deltaKeys {
			fmt.Fprintf(&b, "- %s\n", k)
		}
	}
	b.WriteString("\n---\n\n")

	if len(deltaKeys) == 0 {
		b.WriteString("**delta 없음.** fixpoint 후에도 어떤 SA도 추가 권한을 흡수하지 못함.\n\n")
		return b.String()
	}

	initialBySAStr := map[string]*PermissionSet{}
	for sa, ps := range initialPerms {
		initialBySAStr[saStr(sa)] = ps
	}

	for _, saStrK := range deltaKeys {
		info := delta[saStrK]
		fmt.Fprintf(&b, "## %s\n\n", saStrK)
		initCount, _ := info["initial_perm_count"].(int)
		finalCount, _ := info["final_perm_count"].(int)
		absorbed, _ := info["newly_absorbed"].([]map[string]any)
		fmt.Fprintf(&b, "- 초기 권한 수: %d → 최종 권한 수: %d (+%d)\n\n",
			initCount, finalCount, len(absorbed))

		b.WriteString("**기존 권한 목록:**\n\n")
		initialPS := initialBySAStr[saStrK]
		var initialReprs []string
		if initialPS != nil {
			for _, p := range initialPS.Iter() {
				initialReprs = append(initialReprs, permRepr(p))
			}
			sort.Strings(initialReprs)
		}
		if len(initialReprs) == 0 {
			b.WriteString("- (없음)\n")
		} else {
			for _, r := range initialReprs {
				fmt.Fprintf(&b, "- `%s`\n", r)
			}
		}
		b.WriteString("\n")

		byTransition := map[string][]string{}
		for _, entry := range absorbed {
			vts, _ := entry["via_transitions"].([]string)
			repr, _ := entry["permission_repr"].(string)
			ts := vts
			if len(ts) == 0 {
				ts = []string{"(direct 영수증만)"}
			}
			for _, tid := range ts {
				byTransition[tid] = append(byTransition[tid], repr)
			}
		}
		tids := make([]string, 0, len(byTransition))
		for k := range byTransition {
			tids = append(tids, k)
		}
		sort.Strings(tids)
		for _, tid := range tids {
			fmt.Fprintf(&b, "**탐지된 룰셋: %s**\n\n", tid)
			b.WriteString("추가된 권한:\n")
			for _, perm := range byTransition[tid] {
				fmt.Fprintf(&b, "- `%s`\n", perm)
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

// ----------------------------------------------------------------------------
// 공개 API
// ----------------------------------------------------------------------------

// DumpOutputs — Python dump_outputs() 1:1.
//
// outDir 가 "" 이면 cwd 의 output-go 로 떨군다. (이 레포엔 fixpoint/ 디렉토리가
// 없으므로 Python DEFAULT_OUT_DIR 대신 실제 산출물 위치인 output-go 를 기본값으로.)
func DumpOutputs(
	allPerms map[snapshot.SAKey]*PermissionSet,
	provenance ProvenanceIndex,
	initialPerms map[snapshot.SAKey]*PermissionSet,
	outDir string,
) (string, error) {
	if outDir == "" {
		outDir = "output-go"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	allPermsObj := buildAllPerms(allPerms)
	provObj := buildProvenance(provenance)
	deltaObj := buildDelta(allPerms, initialPerms, provenance)
	deltaMD := buildDeltaMD(deltaObj, allPerms, initialPerms)

	if err := writeJSON(filepath.Join(outDir, "all_perms.json"), allPermsObj); err != nil {
		return "", err
	}
	if err := writeJSON(filepath.Join(outDir, "provenance.json"), provObj); err != nil {
		return "", err
	}
	if err := writeJSON(filepath.Join(outDir, "delta_per_sa.json"), deltaObj); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(outDir, "delta_per_sa.md"), []byte(deltaMD), 0o644); err != nil {
		return "", err
	}
	return outDir, nil
}

func writeJSON(path string, obj any) error {
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// SnapshotInitialPerms — Python snapshot_initial_perms() 1:1.
// PermissionSet 의 deep copy.
func SnapshotInitialPerms(initial map[snapshot.SAKey]*PermissionSet) map[snapshot.SAKey]*PermissionSet {
	out := map[snapshot.SAKey]*PermissionSet{}
	for sa, ps := range initial {
		copy := NewPermissionSet()
		for _, p := range ps.Iter() {
			copy.Add(p)
		}
		out[sa] = copy
	}
	return out
}
