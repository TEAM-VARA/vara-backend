// from_dbeaver_json.go — Python fetch/from_dbeaver_json.py 1:1.
//
// DBeaver JSON export 7개를 모아 snapshot dict 로 변환.
//
// 종료 코드 (Run* 함수 반환값):
//   0 OK / 2 CLI 오류 / 3 export 파일/디렉토리 누락 / 4 5종 공통 snapshot_at 0건.
package loader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 테이블 분류.
var (
	DBJRBACTables = []string{
		"cluster_service_accounts",
		"cluster_cluster_roles",
		"cluster_roles",
		"cluster_cluster_role_bindings",
		"cluster_role_bindings",
	}
	DBJExtraTables = []string{
		"cluster_pods",
		"cluster_nodes",
	}
	DBJTables = append(append([]string{}, DBJRBACTables...), DBJExtraTables...)
)

// rule key snake_case → camelCase 매핑. Python _RULE_KEYMAP 1:1.
var ruleKeymap = map[string]string{
	"api_groups":        "apiGroups",
	"resource_names":    "resourceNames",
	"non_resource_urls": "nonResourceURLs",
}

func convertPolicyRule(rule map[string]any) map[string]any {
	out := make(map[string]any, len(rule))
	for k, v := range rule {
		if nk, ok := ruleKeymap[k]; ok {
			out[nk] = v
		} else {
			out[k] = v
		}
	}
	return out
}

// convertAggregationRule — Python _convert_aggregation_rule 1:1.
// nil 입력 → nil 반환.
func convertAggregationRule(agg any) any {
	if agg == nil {
		return nil
	}
	aggMap, ok := agg.(map[string]any)
	if !ok {
		return nil
	}
	if isEmpty(aggMap) {
		return nil
	}
	selectorsRaw, _ := aggMap["cluster_role_selectors"].([]any)
	converted := make([]map[string]any, 0, len(selectorsRaw))
	for _, s := range selectorsRaw {
		sel, _ := s.(map[string]any)
		if sel == nil {
			continue
		}
		newSel := map[string]any{}
		if v, ok := sel["match_labels"]; ok {
			newSel["matchLabels"] = v
		}
		if v, ok := sel["match_expressions"]; ok {
			newSel["matchExpressions"] = v
		}
		converted = append(converted, newSel)
	}
	return map[string]any{"clusterRoleSelectors": converted}
}

func isEmpty(m map[string]any) bool { return len(m) == 0 }

// coerceJsonb — Python _coerce_jsonb 1:1.
// jsonb 컬럼이 DBeaver export 시점에 string 으로 들어와 있을 수 있음.
// dict/list 면 그대로, string 이면 json.Unmarshal 시도, 실패하면 원본 string 반환.
func coerceJsonb(value any) any {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case map[string]any, []any:
		return value
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		var decoded any
		if err := json.Unmarshal([]byte(s), &decoded); err == nil {
			return decoded
		}
		return value
	}
	return value
}

// readTableJSON — Python _read_table_json 1:1.
// 최상위 array, 또는 {table_name: [...]} dict 모두 허용.
func readTableJSON(dirPath, table string) ([]any, error) {
	path := filepath.Join(dirPath, table+".json")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("error: export file missing: %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error: read %s: %w", path, err)
	}
	// utf-8-sig 처리 — BOM 제거.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(raw)) == 0 {
		return []any{}, nil
	}
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("error: %s JSON parse failed: %v", path, err)
	}
	switch d := data.(type) {
	case []any:
		return d, nil
	case map[string]any:
		if len(d) == 1 {
			for _, v := range d {
				if arr, ok := v.([]any); ok {
					return arr, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("error: %s top-level is not array nor {table:[...]} dict", path)
}

// snapshot_at 비교용. Python 의 string max() 등가 — DBeaver JSON 의 timestamp 는
// ISO8601 문자열이거나 epoch 숫자일 수 있음. Python str 비교가 lexicographic 이므로
// Go 도 동일하게 처리.
type snapshotAt struct {
	str     string
	isNull  bool
	rawType string // "string", "number", "other"
}

func toSnapshotAt(v any) snapshotAt {
	if v == nil {
		return snapshotAt{isNull: true}
	}
	switch x := v.(type) {
	case string:
		return snapshotAt{str: x, rawType: "string"}
	case float64:
		// JSON number — Python 에서는 int/float 가능. lexicographic 비교는 위험하나
		// from_vara_db.go 가 timestamp 를 isoFormat string 으로 떨구므로 실제 입력은 string.
		return snapshotAt{str: fmt.Sprintf("%v", x), rawType: "number"}
	default:
		return snapshotAt{str: fmt.Sprintf("%v", x), rawType: "other"}
	}
}

func (a snapshotAt) less(b snapshotAt) bool {
	if a.isNull {
		return !b.isNull
	}
	if b.isNull {
		return false
	}
	return a.str < b.str
}

func (a snapshotAt) equal(b snapshotAt) bool {
	if a.isNull != b.isNull {
		return false
	}
	if a.isNull {
		return true
	}
	return a.str == b.str
}

func filterCluster(rows []any, cluster string) []any {
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		if cn, ok := rm["cluster_name"].(string); ok && cn == cluster {
			out = append(out, rm)
		}
	}
	return out
}

func distinctSnapshotAt(rows []any) map[string]bool {
	set := map[string]bool{}
	for _, r := range rows {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		v, ok := rm["snapshot_at"]
		if !ok || v == nil {
			continue
		}
		// Python: set 에 raw value 그대로 넣음. string 또는 int. 비교를 위해 fmt.Sprint.
		set[fmt.Sprint(v)] = true
	}
	return set
}

func maxSnapshotAt(rows []any) (snapshotAt, bool) {
	var best snapshotAt
	first := true
	for _, r := range rows {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		v, ok := rm["snapshot_at"]
		if !ok || v == nil {
			continue
		}
		cur := toSnapshotAt(v)
		if first || best.less(cur) {
			best = cur
			first = false
		}
	}
	if first {
		return snapshotAt{isNull: true}, false
	}
	return best, true
}

func rowsAt(rows []any, at snapshotAt) []map[string]any {
	if at.isNull {
		return nil
	}
	var out []map[string]any
	for _, r := range rows {
		rm, _ := r.(map[string]any)
		if rm == nil {
			continue
		}
		v, ok := rm["snapshot_at"]
		if !ok || v == nil {
			continue
		}
		if toSnapshotAt(v).equal(at) {
			out = append(out, rm)
		}
	}
	return out
}

func commonRBACSnapshotAt(forCluster map[string][]any) (snapshotAt, bool) {
	sets := make([]map[string]bool, 0, len(DBJRBACTables))
	for _, t := range DBJRBACTables {
		sets = append(sets, distinctSnapshotAt(forCluster[t]))
	}
	if len(sets) == 0 {
		return snapshotAt{isNull: true}, false
	}
	// intersection
	common := map[string]bool{}
	for k := range sets[0] {
		common[k] = true
	}
	for _, s := range sets[1:] {
		for k := range common {
			if !s[k] {
				delete(common, k)
			}
		}
	}
	if len(common) == 0 {
		return snapshotAt{isNull: true}, false
	}
	// max (lexicographic)
	var best string
	first := true
	for k := range common {
		if first || k > best {
			best = k
			first = false
		}
	}
	return snapshotAt{str: best, rawType: "string"}, true
}

// ----------------------------------------------------------------------------
// BuildSnapshot — Python build_snapshot() 1:1.
//
// 반환:
//   snapshot map[string]any (nil 이면 RBAC 공통 snapshot_at 없음)
//   forCluster — 진단용
// ----------------------------------------------------------------------------

// BuildSnapshot — DBeaver JSON 폴더에서 snapshot 생성.
func BuildSnapshot(dirPath, cluster string) (map[string]any, map[string][]any, error) {
	rawTables := map[string][]any{}
	for _, t := range DBJTables {
		rows, err := readTableJSON(dirPath, t)
		if err != nil {
			return nil, nil, err
		}
		rawTables[t] = rows
	}
	return BuildSnapshotFromRaw(rawTables, cluster)
}

// BuildSnapshotFromRaw — rawTables(테이블명 → row dict 목록)에서 snapshot 생성.
//
// JSON 파일 경로와 DB 직접 경로가 공유하는 순수 변환부.
// 입력 row 형식만 같으면(컬럼명 키 + jsonb 디코드 + timestamp ISO 문자열)
// 두 경로가 동일한 snapshot 을 만든다 → 결과 동치 보장.
func BuildSnapshotFromRaw(rawTables map[string][]any, cluster string) (map[string]any, map[string][]any, error) {
	forCluster := map[string][]any{}
	for t, rows := range rawTables {
		forCluster[t] = filterCluster(rows, cluster)
	}

	rbacAt, ok := commonRBACSnapshotAt(forCluster)
	if !ok {
		return nil, forCluster, nil
	}

	podsAt, _ := maxSnapshotAt(forCluster["cluster_pods"])
	nodesAt, _ := maxSnapshotAt(forCluster["cluster_nodes"])

	snap := map[string]any{
		"captured_at":           rbacAt.str,
		"captured_at_pods":      snapshotAtToAny(podsAt),
		"captured_at_nodes":     snapshotAtToAny(nodesAt),
		"resource_versions":     map[string]any{},
		"service_accounts":      []any{},
		"roles":                 []any{},
		"cluster_roles":         []any{},
		"role_bindings":         []any{},
		"cluster_role_bindings": []any{},
		"pods":                  []any{},
		"nodes":                 []any{},
	}

	// service_accounts
	{
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_service_accounts"], rbacAt) {
			secrets := coerceJsonb(r["secrets"])
			if secrets == nil {
				secrets = []any{}
			}
			out = append(out, map[string]any{
				"metadata": map[string]any{
					"uid":       r["sa_uid"],
					"name":      r["name"],
					"namespace": r["namespace"],
				},
				"secrets": secrets,
			})
		}
		snap["service_accounts"] = out
	}

	// cluster_roles
	{
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_cluster_roles"], rbacAt) {
			rules := coerceJsonb(r["rules"])
			rulesArr, _ := rules.([]any)
			convertedRules := make([]any, 0, len(rulesArr))
			for _, x := range rulesArr {
				if xm, ok := x.(map[string]any); ok {
					convertedRules = append(convertedRules, convertPolicyRule(xm))
				}
			}
			agg := coerceJsonb(r["aggregation_rule"])
			cr := map[string]any{
				"metadata": map[string]any{
					"uid":  r["role_uid"],
					"name": r["name"],
				},
				"rules": convertedRules,
			}
			if convertedAgg := convertAggregationRule(agg); convertedAgg != nil {
				cr["aggregationRule"] = convertedAgg
			}
			out = append(out, cr)
		}
		snap["cluster_roles"] = out
	}

	// roles
	{
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_roles"], rbacAt) {
			rules := coerceJsonb(r["rules"])
			rulesArr, _ := rules.([]any)
			convertedRules := make([]any, 0, len(rulesArr))
			for _, x := range rulesArr {
				if xm, ok := x.(map[string]any); ok {
					convertedRules = append(convertedRules, convertPolicyRule(xm))
				}
			}
			out = append(out, map[string]any{
				"metadata": map[string]any{
					"uid":       r["role_uid"],
					"name":      r["name"],
					"namespace": r["namespace"],
				},
				"rules": convertedRules,
			})
		}
		snap["roles"] = out
	}

	// cluster_role_bindings
	{
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_cluster_role_bindings"], rbacAt) {
			roleRef := coerceJsonb(r["role_ref"])
			if roleRef == nil {
				roleRef = map[string]any{}
			}
			subjects := coerceJsonb(r["subjects"])
			if subjects == nil {
				subjects = []any{}
			}
			out = append(out, map[string]any{
				"metadata": map[string]any{
					"uid":  r["binding_uid"],
					"name": r["name"],
				},
				"roleRef":  roleRef,
				"subjects": subjects,
			})
		}
		snap["cluster_role_bindings"] = out
	}

	// role_bindings
	{
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_role_bindings"], rbacAt) {
			roleRef := coerceJsonb(r["role_ref"])
			if roleRef == nil {
				roleRef = map[string]any{}
			}
			subjects := coerceJsonb(r["subjects"])
			if subjects == nil {
				subjects = []any{}
			}
			out = append(out, map[string]any{
				"metadata": map[string]any{
					"uid":       r["binding_uid"],
					"name":      r["name"],
					"namespace": r["namespace"],
				},
				"roleRef":  roleRef,
				"subjects": subjects,
			})
		}
		snap["role_bindings"] = out
	}

	// pods
	if !podsAt.isNull {
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_pods"], podsAt) {
			labels := coerceJsonb(r["labels"])
			if labels == nil {
				labels = map[string]any{}
			}
			annotations := coerceJsonb(r["annotations"])
			if annotations == nil {
				annotations = map[string]any{}
			}
			containers := coerceJsonb(r["containers"])
			if containers == nil {
				containers = []any{}
			}
			volumes := coerceJsonb(r["volumes"])
			if volumes == nil {
				volumes = []any{}
			}
			out = append(out, map[string]any{
				"metadata": map[string]any{
					"uid":         r["pod_uid"],
					"name":        r["name"],
					"namespace":   r["namespace"],
					"labels":      labels,
					"annotations": annotations,
				},
				"spec": map[string]any{
					"serviceAccountName": stringOrEmpty(r["service_account"]),
					"nodeName":           stringOrEmpty(r["node"]),
					"containers":         containers,
					"volumes":            volumes,
				},
				"status": map[string]any{
					"phase":        stringOrEmpty(r["phase"]),
					"podIP":        stringOrEmpty(r["pod_ip"]),
					"restartCount": intOrZero(r["restart_count"]),
				},
			})
		}
		snap["pods"] = out
	}

	// nodes
	if !nodesAt.isNull {
		out := []any{}
		for _, r := range rowsAt(forCluster["cluster_nodes"], nodesAt) {
			labels := coerceJsonb(r["labels"])
			if labels == nil {
				labels = map[string]any{}
			}
			podsOnNode := coerceJsonb(r["pods_on_node"])
			if podsOnNode == nil {
				podsOnNode = []any{}
			}
			out = append(out, map[string]any{
				"metadata": map[string]any{
					"uid":    r["node_uid"],
					"name":   r["name"],
					"labels": labels,
				},
				"internalIP":       stringOrEmpty(r["internal_ip"]),
				"externalIP":       stringOrEmpty(r["external_ip"]),
				"status":           stringOrEmpty(r["status"]),
				"kernelVersion":    stringOrEmpty(r["kernel_version"]),
				"osImage":          stringOrEmpty(r["os_image"]),
				"containerRuntime": stringOrEmpty(r["container_runtime"]),
				"kubeletVersion":   stringOrEmpty(r["kubelet_version"]),
				"podsOnNode":       podsOnNode,
			})
		}
		snap["nodes"] = out
	}

	return snap, forCluster, nil
}

func snapshotAtToAny(s snapshotAt) any {
	if s.isNull {
		return nil
	}
	return s.str
}

func stringOrEmpty(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func intOrZero(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	}
	return 0
}

