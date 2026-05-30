// Package sareport — SA 종합 보고서 빌더.
//
// 입력은 모두 map[string]any (json.Unmarshal 결과 형식).
// 호출자가 in-memory 데이터를 가지고 있으면 그대로, 디스크 JSON 이면 ReadJSONObject 로
// 읽어 넘긴다.
//
// 각 SA 별로 다음 정보 종합:
//   1. cluster-admin 도달 가능 여부 (all_perms 에 *,*,* @ ns=* 존재)
//   2. fixpoint 매치 룰셋 목록 (delta 의 via_transitions union)
//   3. 기존 권한 수 / 최종 권한 수
//   4. SA 가 마운트된 Pod 목록 + 이미지
//   5. SA 가 묶인 RoleBinding / ClusterRoleBinding
//
// 자기완결 / 결정적 — Go map iteration 비결정성은 모든 출력 지점에서 정렬로 보정.
package sareport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ----------------------------------------------------------------------------
// 데이터 타입
// ----------------------------------------------------------------------------

type PodRef struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Phase     string   `json:"phase,omitempty"`
	Images    []string `json:"images"`
}

type BindingRef struct {
	Kind      string `json:"kind"`                // RoleBinding / ClusterRoleBinding
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"` // RoleBinding 만
	RoleKind  string `json:"role_kind"`           // Role / ClusterRole
	RoleName  string `json:"role_name"`
}

type SAReport struct {
	SAKey               string       `json:"sa_key"` // "ns/name"
	Namespace           string       `json:"namespace"`
	Name                string       `json:"name"`
	ReachesClusterAdmin bool         `json:"reaches_cluster_admin"`
	InitialPermCount    int          `json:"initial_perm_count"`
	FinalPermCount      int          `json:"final_perm_count"`
	AppliedTransitions  []string     `json:"applied_transitions"`
	UsedByPods          []PodRef     `json:"used_by_pods"`
	DirectBindings      []BindingRef `json:"direct_bindings"`
}

type Summary struct {
	TotalSAs        int `json:"total_sas"`
	ClusterAdminSAs int `json:"cluster_admin_sas"`
	ChangedSAs      int `json:"changed_sas"`
	MountedSAs      int `json:"mounted_sas"`
}

type Report struct {
	SnapshotPath string     `json:"snapshot_path"`
	Summary      Summary    `json:"summary"`
	SAs          []SAReport `json:"sas"`
}

// ----------------------------------------------------------------------------
// 공개 API
// ----------------------------------------------------------------------------

// Build — SA 보고서 in-memory 빌드.
//
// snap, allPerms, delta 는 모두 JSON unmarshal 결과 형식 (map[string]any).
// fixpoint 가 막 만든 in-memory 데이터를 넘기려면 호출자가 같은 형식으로 변환해 줘야 함.
// 가장 단순한 경로: fixpoint.DumpOutputs 가 디스크에 떨군 JSON 을 ReadJSONObject 로 읽어 넘김.
func Build(snapPath string, snap, allPerms, delta map[string]any) Report {
	sas := collectSAs(snap)

	// 1. cluster-admin 도달
	clusterAdminSet := map[string]bool{}
	for saKey, perms := range allPerms {
		permList, _ := perms.([]any)
		for _, p := range permList {
			pm, _ := p.(map[string]any)
			if pm == nil {
				continue
			}
			if isClusterAdmin(pm) {
				clusterAdminSet[saKey] = true
				break
			}
		}
	}

	// 2,3. delta 권한 수 + 매치 룰셋
	type dInfo struct {
		initial int
		final   int
		rules   []string
	}
	dMap := map[string]dInfo{}
	for saKey, v := range delta {
		info, _ := v.(map[string]any)
		if info == nil {
			continue
		}
		initial := getInt(info, "initial_perm_count")
		final := getInt(info, "final_perm_count")
		ruleSet := map[string]struct{}{}
		absorbed, _ := info["newly_absorbed"].([]any)
		for _, e := range absorbed {
			em, _ := e.(map[string]any)
			if em == nil {
				continue
			}
			vts, _ := em["via_transitions"].([]any)
			for _, vt := range vts {
				if s, ok := vt.(string); ok && s != "" {
					ruleSet[s] = struct{}{}
				}
			}
		}
		rl := make([]string, 0, len(ruleSet))
		for r := range ruleSet {
			rl = append(rl, r)
		}
		sort.Strings(rl)
		dMap[saKey] = dInfo{initial, final, rl}
	}
	// delta 에 없는 SA — initial == final == all_perms 길이
	for saKey, perms := range allPerms {
		if _, ok := dMap[saKey]; ok {
			continue
		}
		permList, _ := perms.([]any)
		dMap[saKey] = dInfo{initial: len(permList), final: len(permList), rules: []string{}}
	}

	// 4,5. Pod 마운트 + 이미지
	podsBySA := map[string][]PodRef{}
	mountedSet := map[string]struct{}{}
	pods, _ := snap["pods"].([]any)
	for _, p := range pods {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		meta, _ := pm["metadata"].(map[string]any)
		spec, _ := pm["spec"].(map[string]any)
		status, _ := pm["status"].(map[string]any)
		if meta == nil || spec == nil {
			continue
		}
		podNs, _ := meta["namespace"].(string)
		podName, _ := meta["name"].(string)
		if podNs == "" || podName == "" {
			continue
		}
		saName, _ := spec["serviceAccountName"].(string)
		if saName == "" {
			saName = "default"
		}
		saKey := podNs + "/" + saName
		phase := ""
		if status != nil {
			phase, _ = status["phase"].(string)
		}
		containers, _ := spec["containers"].([]any)
		var images []string
		for _, c := range containers {
			cm, _ := c.(map[string]any)
			if cm == nil {
				continue
			}
			if img, ok := cm["image"].(string); ok && img != "" {
				images = append(images, img)
			}
		}
		podsBySA[saKey] = append(podsBySA[saKey], PodRef{
			Name: podName, Namespace: podNs, Phase: phase, Images: images,
		})
		mountedSet[saKey] = struct{}{}
	}
	for k := range podsBySA {
		ps := podsBySA[k]
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].Namespace != ps[j].Namespace {
				return ps[i].Namespace < ps[j].Namespace
			}
			return ps[i].Name < ps[j].Name
		})
		podsBySA[k] = ps
	}

	// 6. RB / CRB
	bindingsBySA := map[string][]BindingRef{}
	collectBindings := func(arr []any, kind string) {
		for _, b := range arr {
			bm, _ := b.(map[string]any)
			if bm == nil {
				continue
			}
			meta, _ := bm["metadata"].(map[string]any)
			roleRef, _ := bm["roleRef"].(map[string]any)
			subjects, _ := bm["subjects"].([]any)
			if meta == nil || roleRef == nil {
				continue
			}
			bName, _ := meta["name"].(string)
			bNs := ""
			if kind == "RoleBinding" {
				bNs, _ = meta["namespace"].(string)
			}
			roleKind, _ := roleRef["kind"].(string)
			roleName, _ := roleRef["name"].(string)
			for _, s := range subjects {
				sm, _ := s.(map[string]any)
				if sm == nil {
					continue
				}
				skind, _ := sm["kind"].(string)
				if skind != "ServiceAccount" {
					continue
				}
				sNs, _ := sm["namespace"].(string)
				sName, _ := sm["name"].(string)
				if sNs == "" || sName == "" {
					continue
				}
				key := sNs + "/" + sName
				bindingsBySA[key] = append(bindingsBySA[key], BindingRef{
					Kind: kind, Name: bName, Namespace: bNs,
					RoleKind: roleKind, RoleName: roleName,
				})
			}
		}
	}
	if rbs, ok := snap["role_bindings"].([]any); ok {
		collectBindings(rbs, "RoleBinding")
	}
	if crbs, ok := snap["cluster_role_bindings"].([]any); ok {
		collectBindings(crbs, "ClusterRoleBinding")
	}
	for k := range bindingsBySA {
		bs := bindingsBySA[k]
		sort.Slice(bs, func(i, j int) bool {
			if bs[i].Kind != bs[j].Kind {
				return bs[i].Kind < bs[j].Kind
			}
			if bs[i].Namespace != bs[j].Namespace {
				return bs[i].Namespace < bs[j].Namespace
			}
			return bs[i].Name < bs[j].Name
		})
		bindingsBySA[k] = bs
	}

	out := make([]SAReport, 0, len(sas))
	for _, sa := range sas {
		key := sa.Namespace + "/" + sa.Name
		info := dMap[key]
		out = append(out, SAReport{
			SAKey:               key,
			Namespace:           sa.Namespace,
			Name:                sa.Name,
			ReachesClusterAdmin: clusterAdminSet[key],
			InitialPermCount:    info.initial,
			FinalPermCount:      info.final,
			AppliedTransitions:  ensureNotNil(info.rules),
			UsedByPods:          ensureNotNilPods(podsBySA[key]),
			DirectBindings:      ensureNotNilBindings(bindingsBySA[key]),
		})
	}

	return Report{
		SnapshotPath: snapPath,
		Summary: Summary{
			TotalSAs:        len(out),
			ClusterAdminSAs: countTrue(clusterAdminSet),
			ChangedSAs:      len(delta),
			MountedSAs:      len(mountedSet),
		},
		SAs: out,
	}
}

// ReadJSONObject — JSON 파일을 map[string]any 로 읽음. 디스크 입력 경로용.
func ReadJSONObject(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

// WriteJSON — Report 를 JSON 파일로.
func WriteJSON(path string, r Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteMarkdown — Report 를 사람용 markdown 으로.
func WriteMarkdown(path string, r Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# SA 종합 보고서\n\n")
	fmt.Fprintf(&b, "snapshot: `%s`\n\n", r.SnapshotPath)
	fmt.Fprintf(&b, "## 요약\n\n")
	fmt.Fprintf(&b, "| 지표 | 값 |\n|---|---|\n")
	fmt.Fprintf(&b, "| 전체 SA | %d |\n", r.Summary.TotalSAs)
	fmt.Fprintf(&b, "| cluster-admin 도달 가능 SA | %d |\n", r.Summary.ClusterAdminSAs)
	fmt.Fprintf(&b, "| 권한 변동 SA (fixpoint 흡수 발생) | %d |\n", r.Summary.ChangedSAs)
	fmt.Fprintf(&b, "| Pod 에 마운트된 SA | %d |\n\n", r.Summary.MountedSAs)

	fmt.Fprintf(&b, "## ⚠ cluster-admin 도달 가능 SA 목록\n\n")
	hasAdminSA := false
	for _, sa := range r.SAs {
		if sa.ReachesClusterAdmin {
			fmt.Fprintf(&b, "- `%s` (via: %s)\n", sa.SAKey, joinOr(sa.AppliedTransitions, "(direct)"))
			hasAdminSA = true
		}
	}
	if !hasAdminSA {
		fmt.Fprintf(&b, "- (없음)\n")
	}
	fmt.Fprintf(&b, "\n---\n\n")

	for _, sa := range r.SAs {
		fmt.Fprintf(&b, "## %s\n\n", sa.SAKey)
		adminMark := "❌"
		if sa.ReachesClusterAdmin {
			adminMark = "✅ 도달 가능 (위험)"
		}
		rulesStr := "(없음)"
		if len(sa.AppliedTransitions) > 0 {
			rulesStr = strings.Join(sa.AppliedTransitions, ", ")
		}
		fmt.Fprintf(&b, "| 항목 | 값 |\n|---|---|\n")
		fmt.Fprintf(&b, "| cluster-admin 도달 | %s |\n", adminMark)
		fmt.Fprintf(&b, "| 기존 권한 수 | %d |\n", sa.InitialPermCount)
		fmt.Fprintf(&b, "| 최종 권한 수 | %d |\n", sa.FinalPermCount)
		delta := sa.FinalPermCount - sa.InitialPermCount
		fmt.Fprintf(&b, "| 증가 (delta) | %+d |\n", delta)
		fmt.Fprintf(&b, "| 매치 룰셋 | %s |\n", rulesStr)
		fmt.Fprintf(&b, "| 마운트된 Pod | %d |\n", len(sa.UsedByPods))
		fmt.Fprintf(&b, "| Direct Binding | %d |\n\n", len(sa.DirectBindings))

		if len(sa.DirectBindings) > 0 {
			fmt.Fprintf(&b, "### Direct Bindings\n\n")
			for _, bd := range sa.DirectBindings {
				if bd.Namespace == "" {
					fmt.Fprintf(&b, "- **%s** `%s` → %s `%s`\n",
						bd.Kind, bd.Name, bd.RoleKind, bd.RoleName)
				} else {
					fmt.Fprintf(&b, "- **%s** `%s` (ns=%s) → %s `%s`\n",
						bd.Kind, bd.Name, bd.Namespace, bd.RoleKind, bd.RoleName)
				}
			}
			fmt.Fprintf(&b, "\n")
		}

		if len(sa.UsedByPods) > 0 {
			fmt.Fprintf(&b, "### 마운트된 Pod\n\n")
			for _, p := range sa.UsedByPods {
				if p.Phase != "" {
					fmt.Fprintf(&b, "- `%s/%s` (phase=%s)\n", p.Namespace, p.Name, p.Phase)
				} else {
					fmt.Fprintf(&b, "- `%s/%s`\n", p.Namespace, p.Name)
				}
				if len(p.Images) == 0 {
					fmt.Fprintf(&b, "  - 이미지: (없음)\n")
				} else {
					for _, img := range p.Images {
						fmt.Fprintf(&b, "  - 이미지: `%s`\n", img)
					}
				}
			}
			fmt.Fprintf(&b, "\n")
		}

		fmt.Fprintf(&b, "---\n\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// ----------------------------------------------------------------------------
// 내부 helpers
// ----------------------------------------------------------------------------

type nsName struct {
	Namespace string
	Name      string
}

func collectSAs(snap map[string]any) []nsName {
	sas, _ := snap["service_accounts"].([]any)
	out := make([]nsName, 0, len(sas))
	for _, e := range sas {
		sa, _ := e.(map[string]any)
		if sa == nil {
			continue
		}
		meta, _ := sa["metadata"].(map[string]any)
		if meta == nil {
			continue
		}
		ns, _ := meta["namespace"].(string)
		name, _ := meta["name"].(string)
		if ns != "" && name != "" {
			out = append(out, nsName{ns, name})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func isClusterAdmin(p map[string]any) bool {
	return getStr(p, "api_group") == "*" &&
		getStr(p, "resource") == "*" &&
		getStr(p, "verb") == "*" &&
		p["namespace"] == nil &&
		p["resource_name"] == nil &&
		p["non_resource_url"] == nil
}

func getStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch x := v.(type) {
		case int:
			return x
		case float64:
			return int(x)
		}
	}
	return 0
}

func countTrue(m map[string]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}

func ensureNotNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func ensureNotNilPods(s []PodRef) []PodRef {
	if s == nil {
		return []PodRef{}
	}
	return s
}

func ensureNotNilBindings(s []BindingRef) []BindingRef {
	if s == nil {
		return []BindingRef{}
	}
	return s
}

func joinOr(s []string, fallback string) string {
	if len(s) == 0 {
		return fallback
	}
	return strings.Join(s, ", ")
}
