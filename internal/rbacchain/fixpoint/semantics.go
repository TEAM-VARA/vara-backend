// semantics.go — Python fixpoint/semantics.py 1:1.
//
// 17개 transition 함수와 룰 YAML 로드.
package fixpoint

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/vara/backend/internal/rbacchain/snapshot"
	"gopkg.in/yaml.v3"
)

// VaraDebug — VARA_DEBUG=1 환경변수로 켜는 진단 모드.
// 첫 yaml 로딩 결과 타입과 keys 를 stderr 에 출력.
var VaraDebug = os.Getenv("VARA_DEBUG") != ""

// 룰 YAML 은 바이너리에 내장(go:embed)한다 → 런타임에 ./rules 폴더가 없어도 동작.
// 디스크 override 가 필요하면(테스트/디버그) VARA_RULES_DIR 또는 SetRulesDir 사용.
//
//go:embed rules/*/*.yaml
var rulesFS embed.FS

// RulesDir / rulesDirOverridden — 디스크 룰 디렉토리 override.
// 기본은 내장 룰 사용. 둘 중 하나라도 설정되면 디스크에서 읽는다.
var (
	RulesDir           string
	rulesDirOverridden bool
)

func init() {
	if v := os.Getenv("VARA_RULES_DIR"); v != "" {
		RulesDir = v
		rulesDirOverridden = true
	}
}

// SetRulesDir — caller (예: cmd/fixpoint/main.go) 에서 룰 디렉토리 명시.
func SetRulesDir(dir string) {
	RulesDir = dir
	rulesDirOverridden = true
}

// readRuleYAML — override 가 있으면 디스크, 없으면 내장 FS 에서 룰 yaml 을 읽는다.
func readRuleYAML(ruleID string) ([]byte, error) {
	if rulesDirOverridden {
		return os.ReadFile(filepath.Join(RulesDir, ruleID, ruleID+".yaml"))
	}
	return rulesFS.ReadFile("rules/" + ruleID + "/" + ruleID + ".yaml")
}

// ----------------------------------------------------------------------------
// 룰 yaml 캐시. Python @lru_cache 등가.
// ----------------------------------------------------------------------------

var (
	ruleCache   sync.Map // ruleID(string) → map[string]any
	ruleLoadErr sync.Map // ruleID(string) → error
)

func loadRule(ruleID string) (map[string]any, error) {
	if v, ok := ruleCache.Load(ruleID); ok {
		return v.(map[string]any), nil
	}
	if v, ok := ruleLoadErr.Load(ruleID); ok {
		return nil, v.(error)
	}
	data, err := readRuleYAML(ruleID)
	if err != nil {
		ruleLoadErr.Store(ruleID, err)
		return nil, fmt.Errorf("rule load %s: %w", ruleID, err)
	}

	// 1단계: yaml.v3 로 generic interface 로 unmarshal.
	// yaml.v3 가 nested list 안의 map 을 map[string]any 로 줄 수도, 다른 형식으로 줄 수도 있음.
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		ruleLoadErr.Store(ruleID, err)
		return nil, fmt.Errorf("rule yaml %s: %w", ruleID, err)
	}

	// 2단계: yaml → JSON → JSON unmarshal 로 강제 normalize.
	// 이 경로를 거치면 모든 map 은 map[string]any, 모든 list 는 []any 로 통일된다.
	// (encoding/json 의 동작은 결정적이라 yaml.v3 의 버전 차이를 우회 가능.)
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		ruleLoadErr.Store(ruleID, err)
		return nil, fmt.Errorf("rule yaml→json %s: %w", ruleID, err)
	}
	var rule map[string]any
	if err := json.Unmarshal(jsonBytes, &rule); err != nil {
		ruleLoadErr.Store(ruleID, err)
		return nil, fmt.Errorf("rule json %s: %w", ruleID, err)
	}

	if VaraDebug {
		fmt.Fprintf(os.Stderr, "[DEBUG] loadRule %s: keys=", ruleID)
		keys := make([]string, 0, len(rule))
		for k := range rule {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(os.Stderr, "%v\n", keys)
		if v, ok := rule["match_any_of"]; ok {
			fmt.Fprintf(os.Stderr, "  match_any_of type=%T len=", v)
			if lst, ok := v.([]any); ok {
				fmt.Fprintf(os.Stderr, "%d\n", len(lst))
				if len(lst) > 0 {
					fmt.Fprintf(os.Stderr, "  first item type=%T value=%v\n", lst[0], lst[0])
				}
			} else {
				fmt.Fprintf(os.Stderr, "(not []any)\n")
			}
		}
	}

	ruleCache.Store(ruleID, rule)
	return rule, nil
}

// normalizeYAMLMap — yaml.v3 가 map[interface{}]interface{} 를 만들 수 있는 케이스
// 보정. v3 는 기본 map[string]any 지만 안전망.
func normalizeYAMLMap(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = normalizeYAMLMap(vv)
		}
		return x
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalizeYAMLMap(vv)
		}
		return out
	case []any:
		for i, vv := range x {
			x[i] = normalizeYAMLMap(vv)
		}
		return x
	default:
		return v
	}
}

// ----------------------------------------------------------------------------
// transition 함수 시그니처
//
// Python:
//   def transition_R_DIRECT_01(sa, all_perms, snapshot) -> Iterator[...]
//
// Go: callback 스타일. yield 등가는 emit func.
// ----------------------------------------------------------------------------

// TransitionEmit — transition 함수가 결과를 보내는 콜백.
type TransitionEmit func(targetSA snapshot.SAKey, perm Permission, prov map[string]any)

// TransitionFunc — Python transition_R_*(sa, all_perms, snapshot) 등가.
type TransitionFunc func(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet, snap map[string]any, emit TransitionEmit) error

// ----------------------------------------------------------------------------
// snapshot helpers (Tier 1)
// ----------------------------------------------------------------------------

func saKey(sa snapshot.SAKey) string {
	return sa.String()
}

func matches(ruleID string, saPerms *PermissionSet) ([][]Permission, error) {
	rule, err := loadRule(ruleID)
	if err != nil {
		return nil, err
	}
	return EvaluateRule(rule, saPerms)
}

func sasInNamespace(snap map[string]any, ns string) []snapshot.SAKey {
	var out []snapshot.SAKey
	sas, _ := snap["service_accounts"].([]any)
	for _, e := range sas {
		sa, _ := e.(map[string]any)
		if sa == nil {
			continue
		}
		meta, _ := sa["metadata"].(map[string]any)
		if meta == nil {
			continue
		}
		saNS := getStringFromMap(meta, "namespace")
		saName := getStringFromMap(meta, "name")
		if saNS == ns && saName != "" {
			out = append(out, snapshot.SAKey{Namespace: saNS, Name: saName})
		}
	}
	return out
}

func allNamespaces(snap map[string]any) []string {
	set := map[string]struct{}{}
	sas, _ := snap["service_accounts"].([]any)
	for _, e := range sas {
		sa, _ := e.(map[string]any)
		if sa == nil {
			continue
		}
		meta, _ := sa["metadata"].(map[string]any)
		if meta == nil {
			continue
		}
		ns := getStringFromMap(meta, "namespace")
		if ns != "" {
			set[ns] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	return out
}

// ----------------------------------------------------------------------------
// snapshot helpers (Tier 2 — Pod/Node)
// ----------------------------------------------------------------------------

// _pods_in_namespace — ns=="" 면 모든 Pod 반환 (Python ns=None 등가).
func podsInNamespace(snap map[string]any, ns string, allPods bool) []map[string]any {
	var out []map[string]any
	pods, _ := snap["pods"].([]any)
	for _, e := range pods {
		pod, _ := e.(map[string]any)
		if pod == nil {
			continue
		}
		if allPods {
			out = append(out, pod)
			continue
		}
		meta, _ := pod["metadata"].(map[string]any)
		if meta == nil {
			continue
		}
		podNS := getStringFromMap(meta, "namespace")
		if podNS == ns {
			out = append(out, pod)
		}
	}
	return out
}

// saOfPod — Python _sa_of_pod. nil 반환 시 invalid.
func saOfPod(pod map[string]any) (snapshot.SAKey, bool) {
	meta, _ := pod["metadata"].(map[string]any)
	spec, _ := pod["spec"].(map[string]any)
	ns := getStringFromMap(meta, "namespace")
	if ns == "" {
		return snapshot.SAKey{}, false
	}
	saName := getStringFromMap(spec, "serviceAccountName")
	if saName == "" {
		saName = "default"
	}
	return snapshot.SAKey{Namespace: ns, Name: saName}, true
}

func podIsRunning(pod map[string]any) bool {
	status, _ := pod["status"].(map[string]any)
	return getStringFromMap(status, "phase") == "Running"
}

// ----------------------------------------------------------------------------
// 공통 흡수 패턴 helpers
// ----------------------------------------------------------------------------

func absorbClusterAdmin(sa snapshot.SAKey, viaTransition string, matchedPerms []Permission, emit TransitionEmit) {
	prov := MakeTransitionProvenance(viaTransition, saKey(sa), matchedPerms, "")
	emit(sa, ClusterAdmin, prov)
}

func absorbNSSAs(
	callerSA snapshot.SAKey,
	targetNS snapshot.NullString,
	allPerms map[snapshot.SAKey]*PermissionSet,
	snap map[string]any,
	viaTransition string,
	matchedPerms []Permission,
	emit TransitionEmit,
) {
	var targetNSList []string
	if targetNS.IsNull {
		targetNSList = allNamespaces(snap)
		sort.Strings(targetNSList)
	} else {
		targetNSList = []string{targetNS.Value}
	}
	for _, ns := range targetNSList {
		for _, targetSA := range sasInNamespace(snap, ns) {
			ps, ok := allPerms[targetSA]
			if !ok {
				continue
			}
			absorbedFrom := saKey(targetSA)
			for _, absorbedPerm := range ps.Iter() {
				prov := MakeTransitionProvenance(viaTransition, saKey(callerSA), matchedPerms, absorbedFrom)
				emit(callerSA, absorbedPerm, prov)
			}
		}
	}
}

func absorbPodSA(
	callerSA snapshot.SAKey,
	targetPod map[string]any,
	allPerms map[snapshot.SAKey]*PermissionSet,
	viaTransition string,
	matchedPerms []Permission,
	emit TransitionEmit,
) {
	targetSA, ok := saOfPod(targetPod)
	if !ok {
		return
	}
	ps, ok := allPerms[targetSA]
	if !ok {
		return
	}
	absorbedFrom := saKey(targetSA)
	for _, absorbedPerm := range ps.Iter() {
		prov := MakeTransitionProvenance(viaTransition, saKey(callerSA), matchedPerms, absorbedFrom)
		emit(callerSA, absorbedPerm, prov)
	}
}

func absorbAllPodsSA(
	callerSA snapshot.SAKey,
	allPerms map[snapshot.SAKey]*PermissionSet,
	snap map[string]any,
	viaTransition string,
	matchedPerms []Permission,
	emit TransitionEmit,
) {
	pods, _ := snap["pods"].([]any)
	for _, e := range pods {
		pod, _ := e.(map[string]any)
		if pod == nil {
			continue
		}
		absorbPodSA(callerSA, pod, allPerms, viaTransition, matchedPerms, emit)
	}
}

// ----------------------------------------------------------------------------
// 그룹 A: cluster-admin 직행 (7개)
// ----------------------------------------------------------------------------

func makeClusterAdminTransition(ruleID string) TransitionFunc {
	return func(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet, snap map[string]any, emit TransitionEmit) error {
		m, err := matches(ruleID, allPerms[sa])
		if err != nil {
			return err
		}
		if len(m) > 0 {
			absorbClusterAdmin(sa, ruleID, m[0], emit)
		}
		return nil
	}
}

var (
	TransitionRDirect01    = makeClusterAdminTransition("R-DIRECT-01")
	TransitionRDirect02    = makeClusterAdminTransition("R-DIRECT-02")
	TransitionRDirect03    = makeClusterAdminTransition("R-DIRECT-03")
	TransitionRIndirect07  = makeClusterAdminTransition("R-INDIRECT-07")
	TransitionRIndirect08  = makeClusterAdminTransition("R-INDIRECT-08")
	TransitionRIndirect09  = makeClusterAdminTransition("R-INDIRECT-09")
	TransitionRIndirect18  = makeClusterAdminTransition("R-INDIRECT-18")
)

// ----------------------------------------------------------------------------
// 그룹 B: ns 임의 SA 흡수 (4개)
// ----------------------------------------------------------------------------

func makeNSAbsorbTransition(ruleID string) TransitionFunc {
	return func(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet, snap map[string]any, emit TransitionEmit) error {
		mtch, err := matches(ruleID, allPerms[sa])
		if err != nil {
			return err
		}
		for _, matchGroup := range mtch {
			triggeringPerm := matchGroup[0]
			absorbNSSAs(sa, triggeringPerm.Namespace, allPerms, snap, ruleID, matchGroup, emit)
		}
		return nil
	}
}

var (
	TransitionRIndirect01 = makeNSAbsorbTransition("R-INDIRECT-01")
	TransitionRIndirect04 = makeNSAbsorbTransition("R-INDIRECT-04")
	TransitionRIndirect06 = makeNSAbsorbTransition("R-INDIRECT-06")
	TransitionRIndirect17 = makeNSAbsorbTransition("R-INDIRECT-17")
)

// ----------------------------------------------------------------------------
// 그룹 C: 특정 Pod 인스턴스 SA 흡수 (2개)
// ----------------------------------------------------------------------------

func makePodInstanceTransition(ruleID string) TransitionFunc {
	return func(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet, snap map[string]any, emit TransitionEmit) error {
		mtch, err := matches(ruleID, allPerms[sa])
		if err != nil {
			return err
		}
		for _, matchGroup := range mtch {
			triggeringPerm := matchGroup[0]
			targetNS := triggeringPerm.Namespace
			pods := podsInNamespace(snap, targetNS.Value, targetNS.IsNull)
			for _, pod := range pods {
				if !podIsRunning(pod) {
					continue
				}
				absorbPodSA(sa, pod, allPerms, ruleID, matchGroup, emit)
			}
		}
		return nil
	}
}

var (
	TransitionRIndirect02 = makePodInstanceTransition("R-INDIRECT-02")
	TransitionRIndirect03 = makePodInstanceTransition("R-INDIRECT-03")
)

// ----------------------------------------------------------------------------
// 그룹 D: 노드 위 Pod SA 흡수 (2개)
// ----------------------------------------------------------------------------

func makeAllPodsTransition(ruleID string) TransitionFunc {
	return func(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet, snap map[string]any, emit TransitionEmit) error {
		mtch, err := matches(ruleID, allPerms[sa])
		if err != nil {
			return err
		}
		for _, matchGroup := range mtch {
			absorbAllPodsSA(sa, allPerms, snap, ruleID, matchGroup, emit)
		}
		return nil
	}
}

var (
	TransitionRIndirect11 = makeAllPodsTransition("R-INDIRECT-11")
	TransitionRIndirect15 = makeAllPodsTransition("R-INDIRECT-15")
)

// ----------------------------------------------------------------------------
// 그룹 G: schema v1 multi-step (1개) — R-INDIRECT-19
// ----------------------------------------------------------------------------

func TransitionRIndirect19(sa snapshot.SAKey, allPerms map[snapshot.SAKey]*PermissionSet, snap map[string]any, emit TransitionEmit) error {
	mtch, err := matches("R-INDIRECT-19", allPerms[sa])
	if err != nil {
		return err
	}
	for _, matchGroup := range mtch {
		// match_all_of: items 순서 = yaml 순서 (pods 먼저)
		podsPerm := matchGroup[0]
		targetNS := podsPerm.Namespace
		if targetNS.IsNull {
			absorbAllPodsSA(sa, allPerms, snap, "R-INDIRECT-19", matchGroup, emit)
		} else {
			for _, pod := range podsInNamespace(snap, targetNS.Value, false) {
				absorbPodSA(sa, pod, allPerms, "R-INDIRECT-19", matchGroup, emit)
			}
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// 그룹 F: 옵트인 (1개) — R-INDIRECT-16
// ----------------------------------------------------------------------------

var TransitionRIndirect16 = makeClusterAdminTransition("R-INDIRECT-16")

// ----------------------------------------------------------------------------
// 카탈로그
// ----------------------------------------------------------------------------

// GroupATransitions — Python GROUP_A_TRANSITIONS 1:1.
var GroupATransitions = []TransitionFunc{
	TransitionRDirect01,
	TransitionRDirect02,
	TransitionRDirect03,
	TransitionRIndirect07,
	TransitionRIndirect08,
	TransitionRIndirect09,
	TransitionRIndirect18,
}

var GroupBTransitions = []TransitionFunc{
	TransitionRIndirect01,
	TransitionRIndirect04,
	TransitionRIndirect06,
	TransitionRIndirect17,
}

var GroupCTransitions = []TransitionFunc{
	TransitionRIndirect02,
	TransitionRIndirect03,
}

var GroupDTransitions = []TransitionFunc{
	TransitionRIndirect11,
	TransitionRIndirect15,
}

var GroupGTransitions = []TransitionFunc{
	TransitionRIndirect19,
}

// AllTransitions — default 카탈로그 (옵트인 제외).
var AllTransitions = func() []TransitionFunc {
	var out []TransitionFunc
	out = append(out, GroupATransitions...)
	out = append(out, GroupBTransitions...)
	out = append(out, GroupCTransitions...)
	out = append(out, GroupDTransitions...)
	out = append(out, GroupGTransitions...)
	return out
}()

// OptInTransitions — flag → transition 매핑. Python OPT_IN_TRANSITIONS 등가.
var OptInTransitions = map[string][]TransitionFunc{
	"include-eks-specific": {TransitionRIndirect16},
}

// TransitionsForFlags — Python transitions_for_flags() 1:1.
func TransitionsForFlags(activeFlags map[string]struct{}) []TransitionFunc {
	out := make([]TransitionFunc, 0, len(AllTransitions))
	out = append(out, AllTransitions...)
	// Python dict 순회 순서는 삽입 순서. Go 도 그에 맞추되 결과 동치는 set 의미라 무관.
	for flag, transitions := range OptInTransitions {
		if _, ok := activeFlags[flag]; ok {
			out = append(out, transitions...)
		}
	}
	return out
}
