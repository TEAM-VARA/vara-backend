// Package directperm — Python direct_perm/extract.py 1:1.
//
// snapshot 에서 direct 권한 추출.
//
// 설계 원칙(CLAUDE.md):
//   (3) 유연성 금지 (4) 자동성 (5) 정확성
package directperm

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// WarningKind — Python enum WarningKind 1:1.
type WarningKind string

const (
	WBindingReferencesMissingRole       WarningKind = "binding_references_missing_role"
	WBindingReferencesMissingSA         WarningKind = "binding_references_missing_sa"
	WClusterRoleBindingReferencesRole   WarningKind = "clusterrolebinding_references_role"
	WServiceAccountSubjectMissingNS     WarningKind = "service_account_subject_missing_namespace"
	WUserSubjectNotTrackedToSA          WarningKind = "user_subject_not_tracked_to_sa"
	WUnhandledGroupSubject              WarningKind = "unhandled_group_subject"
	WAggregationRulesEmpty              WarningKind = "aggregation_rules_empty"
	WNonResourceURLInRole               WarningKind = "non_resource_url_in_role"
	WUnknownSubjectKind                 WarningKind = "unknown_subject_kind"
	WPolicyRuleInvalid                  WarningKind = "policy_rule_invalid"
)

// KnownLimitations — Python KNOWN_LIMITATIONS 1:1.
var KnownLimitations = []string{
	"User subject로 직접 받은 권한은 SA로 추적되지 않음. user_permissions에 별도 보관. " +
		"User -> SA 권한 흐름 분석은 Phase 4 예정.",
	"Group subject 중 system:serviceaccounts / system:serviceaccounts:<ns>만 자동 멤버십 " +
		"해결. 그 외 그룹(system:masters, system:authenticated, system:unauthenticated, " +
		"system:nodes, kubeadm:cluster-admins, 사용자 정의 그룹 등)은 group_permissions에 " +
		"별도 보관. SA 멤버십은 외부 정보(IdP, 노드 인증서 등) 없이는 자동 결정 불가.",
	"list / watch + resourceNames: K8s는 인가 시 클라이언트가 metadata.name field " +
		"selector를 동반해야 인가. 정적 분석에서는 클라이언트 측 조건을 알 수 없어 좁은 " +
		"권한 그대로 보관. 권한 상승 분석에는 영향 적음.",
	"nonResourceURLs(예: /healthz, /metrics)는 별도 차원으로 추적. resource 권한과 " +
		"covers()에서 안 섞임. K8s 공식 suffix glob('/api/*' = /api/로 시작하는 모든 경로)은 " +
		"보관 단계에서는 원본 문자열 그대로 둔다 — prefix 매칭은 covers() 단계에서 처리.",
	"aggregationRule만 있고 .rules가 비어 있는 ClusterRole은 권한 0개로 취급 + warning. " +
		"apiserver 경유 snapshot에서는 aggregation controller가 채워줘야 정상.",
	"snapshot은 단일 형식(이 프로젝트의 apiserver dump JSON)만 받음. 키 누락 시 " +
		"ValueError. (3) 유연성 금지 원칙에 따라 형식별 어댑터를 두지 않음.",
}

// Python _RESOURCENAME_IGNORED_VERBS 등가.
var resourceNameIgnoredVerbs = map[string]struct{}{
	"create":           {},
	"deletecollection": {},
}

// ----------------------------------------------------------------------------
// 내부 state
// ----------------------------------------------------------------------------

type nsName struct {
	Namespace string
	Name      string
}

type extractState struct {
	saPermissions    map[string][]map[string]any
	groupPermissions map[string][]map[string]any
	userPermissions  map[string][]map[string]any
	warnings         []map[string]any
}

func (s *extractState) warn(kind WarningKind, message string, context map[string]any) {
	s.warnings = append(s.warnings, map[string]any{
		"kind":    string(kind),
		"message": message,
		"context": context,
	})
}

// ----------------------------------------------------------------------------
// 인덱싱
// ----------------------------------------------------------------------------

func indexSAs(snap map[string]any) map[nsName]struct{} {
	idx := map[nsName]struct{}{}
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
		ns, _ := meta["namespace"].(string)
		name, _ := meta["name"].(string)
		if ns != "" && name != "" {
			idx[nsName{ns, name}] = struct{}{}
		}
	}
	return idx
}

// roleKey — ("Role"|"ClusterRole", namespace_or_None, name). Go 에서는 struct.
// namespaceIsNull == true 이면 namespace=cluster scope.
type roleKey struct {
	Kind             string
	Namespace        string
	NamespaceIsNull  bool
	Name             string
}

func indexRoles(snap map[string]any) map[roleKey]map[string]any {
	idx := map[roleKey]map[string]any{}
	roles, _ := snap["roles"].([]any)
	for _, e := range roles {
		r, _ := e.(map[string]any)
		if r == nil {
			continue
		}
		meta, _ := r["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		ns, _ := meta["namespace"].(string)
		name, _ := meta["name"].(string)
		// Role 은 namespace 필수, 없으면 그대로 빈 string 으로
		idx[roleKey{Kind: "Role", Namespace: ns, NamespaceIsNull: ns == "", Name: name}] = r
	}
	crs, _ := snap["cluster_roles"].([]any)
	for _, e := range crs {
		cr, _ := e.(map[string]any)
		if cr == nil {
			continue
		}
		meta, _ := cr["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		name, _ := meta["name"].(string)
		idx[roleKey{Kind: "ClusterRole", NamespaceIsNull: true, Name: name}] = cr
	}
	return idx
}

func groupSAsByNamespace(snap map[string]any) map[string][]nsName {
	out := map[string][]nsName{}
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
		ns, _ := meta["namespace"].(string)
		name, _ := meta["name"].(string)
		if ns != "" && name != "" {
			out[ns] = append(out[ns], nsName{ns, name})
		}
	}
	return out
}

// ----------------------------------------------------------------------------
// Permission dedup
// ----------------------------------------------------------------------------

// _perm_signature — Python tuple. Go 에서는 string concat (또는 struct).
func permSignature(perm map[string]any) string {
	return fmt.Sprintf("%v|%v|%v|%v|%v|%v",
		perm["api_group"], perm["resource"], perm["verb"],
		perm["namespace"], perm["resource_name"], perm["non_resource_url"])
}

func provSignature(prov map[string]any) string {
	return fmt.Sprintf("%v|%v|%v|%v|%v|%v|%v|%v|%v",
		prov["binding_kind"], prov["binding_namespace"], prov["binding_name"],
		prov["role_kind"], prov["role_name"], prov["policy_rule_index"],
		prov["subject_kind"], prov["subject_namespace"], prov["subject_name"])
}

// _add_permissions — Python _add_permissions 1:1.
// provenance 필드는 []any 로 통일 (makePerm 과 일관).
func addPermissions(bucket map[string][]map[string]any, key string, perms []map[string]any) {
	existing, ok := bucket[key]
	if !ok {
		existing = []map[string]any{}
	}
	existingBySig := map[string]map[string]any{}
	for _, p := range existing {
		existingBySig[permSignature(p)] = p
	}
	for _, p := range perms {
		sig := permSignature(p)
		if cur, ok := existingBySig[sig]; ok {
			curProvSigs := map[string]struct{}{}
			curProv := toAnySliceProv(cur["provenance"])
			for _, pr := range curProv {
				if prm, ok := pr.(map[string]any); ok {
					curProvSigs[provSignature(prm)] = struct{}{}
				}
			}
			pProv := toAnySliceProv(p["provenance"])
			for _, pr := range pProv {
				prm, ok := pr.(map[string]any)
				if !ok {
					continue
				}
				prSig := provSignature(prm)
				if _, exists := curProvSigs[prSig]; !exists {
					curProv = append(curProv, prm)
					curProvSigs[prSig] = struct{}{}
				}
			}
			cur["provenance"] = curProv
		} else {
			existing = append(existing, p)
			existingBySig[sig] = p
		}
	}
	bucket[key] = existing
}

// toAnySliceProv — provenance 필드 값을 []any 로 normalize.
// []any 또는 []map[string]any 어느 쪽이든 받아서 []any 반환.
func toAnySliceProv(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	}
	return nil
}

// ----------------------------------------------------------------------------
// PolicyRule 펼침
// ----------------------------------------------------------------------------

func isSubresource(resource string) bool { return strings.Contains(resource, "/") }

// expandPolicyRule — Python _expand_policy_rule 1:1.
// effNamespace == "" + effNamespaceIsNull == true 이면 cluster-wide.
func expandPolicyRule(
	rule map[string]any,
	ruleIndex int,
	effNamespace string,
	effNamespaceIsNull bool,
	provBase map[string]any,
	state *extractState,
) []map[string]any {
	verbs := asStringList(rule["verbs"])
	apiGroups := asStringList(rule["apiGroups"])
	resources := asStringList(rule["resources"])
	resourceNames := asStringList(rule["resourceNames"])
	nonResourceURLs := asStringList(rule["nonResourceURLs"])

	var perms []map[string]any

	// 1) nonResourceURLs 차원
	if len(nonResourceURLs) > 0 {
		if provBase["role_kind"] == "Role" {
			state.warn(WNonResourceURLInRole,
				fmt.Sprintf("Role(%v) PolicyRule[%d]: nonResourceURLs가 Role에 존재 — K8s 스키마상 비정상.",
					provBase["role_name"], ruleIndex),
				map[string]any{
					"role_kind":  "Role",
					"role_name":  provBase["role_name"],
					"rule_index": ruleIndex,
				})
		}
		for _, url := range nonResourceURLs {
			for _, verb := range verbs {
				perms = append(perms, makePerm(
					"", "", verb,
					"", true, // namespace=None
					"", true, // resource_name=None
					url, false, // non_resource_url 값 있음
					provBase, ruleIndex,
				))
			}
		}
	}

	// 2) resource 차원
	if len(apiGroups) > 0 && len(resources) > 0 && len(verbs) > 0 {
		for _, ag := range apiGroups {
			for _, res := range resources {
				for _, verb := range verbs {
					var rnList []struct {
						val    string
						isNull bool
					}
					_, ignoredVerb := resourceNameIgnoredVerbs[verb]
					if !isSubresource(res) && ignoredVerb {
						rnList = []struct {
							val    string
							isNull bool
						}{{"", true}}
					} else if len(resourceNames) > 0 {
						for _, rn := range resourceNames {
							rnList = append(rnList, struct {
								val    string
								isNull bool
							}{rn, false})
						}
					} else {
						rnList = []struct {
							val    string
							isNull bool
						}{{"", true}}
					}
					for _, rn := range rnList {
						perms = append(perms, makePerm(
							ag, res, verb,
							effNamespace, effNamespaceIsNull,
							rn.val, rn.isNull,
							"", true, // non_resource_url=None
							provBase, ruleIndex,
						))
					}
				}
			}
		}
	} else if (len(apiGroups) > 0 || len(resources) > 0 || len(verbs) > 0) && len(nonResourceURLs) == 0 {
		state.warn(WPolicyRuleInvalid,
			fmt.Sprintf("%v(%v) PolicyRule[%d]: apiGroups/resources/verbs 중 일부만 채워짐.",
				provBase["role_kind"], provBase["role_name"], ruleIndex),
			map[string]any{
				"role_kind":       provBase["role_kind"],
				"role_name":       provBase["role_name"],
				"rule_index":      ruleIndex,
				"verbs_empty":     len(verbs) == 0,
				"apiGroups_empty": len(apiGroups) == 0,
				"resources_empty": len(resources) == 0,
			})
	}

	return perms
}

func makePerm(
	apiGroup, resource, verb string,
	namespace string, namespaceIsNull bool,
	resourceName string, resourceNameIsNull bool,
	nonResourceURL string, nonResourceURLIsNull bool,
	provBase map[string]any, ruleIndex int,
) map[string]any {
	prov := map[string]any{}
	for k, v := range provBase {
		prov[k] = v
	}
	prov["policy_rule_index"] = ruleIndex
	// provenance 는 []any 로 통일 — fixpoint.InitialProvenanceFromDP 가
	// .([]any) 로 type assertion 하므로 []map[string]any 면 실패한다.
	// JSON 직렬화 결과는 동일하지만 in-memory 타입은 []any 필수.
	return map[string]any{
		"api_group":        apiGroup,
		"resource":         resource,
		"verb":             verb,
		"namespace":        nullableString(namespace, namespaceIsNull),
		"resource_name":    nullableString(resourceName, resourceNameIsNull),
		"non_resource_url": nullableString(nonResourceURL, nonResourceURLIsNull),
		"provenance":       []any{prov},
	}
}

func nullableString(v string, isNull bool) any {
	if isNull {
		return nil
	}
	return v
}

// getOptionalString — Python dict.get(key) 등가.
// key 없음 또는 value=None → ("", true)  [Python None]
// value 가 string("") 인 경우 → ("", false) [Python ""]
// value 가 string("foo") → ("foo", false)
func getOptionalString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", true
	}
	s, ok := v.(string)
	if !ok {
		return "", true
	}
	return s, false
}

func asStringList(v any) []string {
	if v == nil {
		return nil
	}
	lst, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(lst))
	for _, e := range lst {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

// ----------------------------------------------------------------------------
// Binding 처리
// ----------------------------------------------------------------------------

func processBinding(
	binding map[string]any,
	bindingKind string,
	roleIndex map[roleKey]map[string]any,
	saIndex map[nsName]struct{},
	nsToSAs map[string][]nsName,
	allSAs []nsName,
	state *extractState,
) {
	meta, _ := binding["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	bindingName, _ := meta["name"].(string)
	// Python: binding_ns = meta.get("namespace")
	//   - key 없음 또는 None → None
	//   - "" (빈 문자열) → "" (not None, but falsy)
	//   - 정상 ns 문자열 → 그 문자열
	// Go 에서 None 등가는 nil. nil-distinct 하게 유지.
	bindingNS, bindingNSIsNull := getOptionalString(meta, "namespace")

	roleRef, _ := binding["roleRef"].(map[string]any)
	if roleRef == nil {
		roleRef = map[string]any{}
	}
	roleRefKind, _ := roleRef["kind"].(string)
	roleRefName, _ := roleRef["name"].(string)

	if bindingKind == "ClusterRoleBinding" && roleRefKind == "Role" {
		state.warn(WClusterRoleBindingReferencesRole,
			fmt.Sprintf("ClusterRoleBinding(%s) → Role(%s): K8s 스키마상 ClusterRoleBinding은 ClusterRole만 참조 가능. binding skip.",
				bindingName, roleRefName),
			map[string]any{
				"binding":   bindingName,
				"role_kind": "Role",
				"role_name": roleRefName,
			})
		return
	}

	var key roleKey
	switch roleRefKind {
	case "Role":
		key = roleKey{Kind: "Role", Namespace: bindingNS, NamespaceIsNull: bindingNSIsNull, Name: roleRefName}
	case "ClusterRole":
		key = roleKey{Kind: "ClusterRole", NamespaceIsNull: true, Name: roleRefName}
	default:
		state.warn(WBindingReferencesMissingRole,
			fmt.Sprintf("%s(%s): roleRef.kind 알 수 없음: %q",
				bindingKind, bindingName, roleRefKind),
			map[string]any{
				"binding":   bindingName,
				"role_kind": roleRefKind,
				"role_name": roleRefName,
			})
		return
	}

	role, ok := roleIndex[key]
	if !ok {
		state.warn(WBindingReferencesMissingRole,
			fmt.Sprintf("%s(%s): roleRef %s(%s)가 snapshot에 없음. binding skip.",
				bindingKind, bindingName, roleRefKind, roleRefName),
			map[string]any{
				"binding":      bindingName,
				"binding_kind": bindingKind,
				"role_kind":    roleRefKind,
				"role_name":    roleRefName,
			})
		return
	}

	// effective namespace
	effNS := ""
	effNSIsNull := true
	if bindingKind == "RoleBinding" {
		effNS = bindingNS
		effNSIsNull = bindingNSIsNull
	}

	// rules
	var rules []map[string]any
	if rl, ok := role["rules"].([]any); ok {
		for _, e := range rl {
			if m, ok := e.(map[string]any); ok {
				rules = append(rules, m)
			}
		}
	}
	hasAgg := false
	if _, ok := role["aggregationRule"]; ok && role["aggregationRule"] != nil {
		hasAgg = true
	}
	if len(rules) == 0 && hasAgg {
		state.warn(WAggregationRulesEmpty,
			fmt.Sprintf("%s(%s): aggregationRule 있지만 .rules=[] — controller 미동작 또는 자식 0개.",
				roleRefKind, roleRefName),
			map[string]any{
				"role_kind": roleRefKind,
				"role_name": roleRefName,
				"binding":   bindingName,
			})
	}

	subjects, _ := binding["subjects"].([]any)
	for _, e := range subjects {
		subject, _ := e.(map[string]any)
		if subject == nil {
			continue
		}
		processSubject(
			subject,
			bindingKind, bindingName, bindingNS, bindingNSIsNull,
			roleRefKind, roleRefName,
			rules, effNS, effNSIsNull,
			saIndex, nsToSAs, allSAs, state,
		)
	}
}

func processSubject(
	subject map[string]any,
	bindingKind, bindingName string,
	bindingNS string, bindingNSIsNull bool,
	roleKindStr, roleName string,
	rules []map[string]any,
	effNS string, effNSIsNull bool,
	saIndex map[nsName]struct{},
	nsToSAs map[string][]nsName,
	allSAs []nsName,
	state *extractState,
) {
	sKind, _ := subject["kind"].(string)
	sName, _ := subject["name"].(string)
	// Python: s_ns = subject.get("namespace") — None if 키 없음/None.
	sNS, sNSIsNull := getOptionalString(subject, "namespace")

	provBase := map[string]any{
		"binding_kind":      bindingKind,
		"binding_namespace": nullableString(bindingNS, bindingNSIsNull),
		"binding_name":      bindingName,
		"role_kind":         roleKindStr,
		"role_name":         roleName,
		"subject_kind":      sKind,
		"subject_namespace": nullableString(sNS, sNSIsNull),
		"subject_name":      sName,
	}

	var expanded []map[string]any
	for idx, rule := range rules {
		expanded = append(expanded, expandPolicyRule(rule, idx, effNS, effNSIsNull, provBase, state)...)
	}

	switch sKind {
	case "ServiceAccount":
		if sNSIsNull {
			state.warn(WServiceAccountSubjectMissingNS,
				fmt.Sprintf("%s(%s) subject ServiceAccount(%s): namespace 누락 — K8s 스키마상 invalid.",
					bindingKind, bindingName, sName),
				map[string]any{
					"binding":      bindingName,
					"subject_name": sName,
				})
			return
		}
		if _, ok := saIndex[nsName{sNS, sName}]; !ok {
			state.warn(WBindingReferencesMissingSA,
				fmt.Sprintf("%s(%s) → ServiceAccount(%s/%s): SA가 snapshot에 없음. 권한 안 매달림.",
					bindingKind, bindingName, sNS, sName),
				map[string]any{
					"binding":           bindingName,
					"subject_namespace": sNS,
					"subject_name":      sName,
				})
			return
		}
		addPermissions(state.saPermissions, sNS+"/"+sName, expanded)

	case "User":
		state.warn(WUserSubjectNotTrackedToSA,
			fmt.Sprintf("%s(%s) → User(%s): SA 흐름 미추적. 권한은 user_permissions['%s']에 별도 보관.",
				bindingKind, bindingName, sName, sName),
			map[string]any{
				"binding": bindingName,
				"user":    sName,
			})
		addPermissions(state.userPermissions, sName, expanded)

	case "Group":
		targetSAs, resolved := resolveGroupToSAs(sName, nsToSAs, allSAs)
		if resolved {
			for _, sa := range targetSAs {
				addPermissions(state.saPermissions, sa.Namespace+"/"+sa.Name, expanded)
			}
		} else {
			state.warn(WUnhandledGroupSubject,
				fmt.Sprintf("%s(%s) → Group(%s): SA 멤버십 자동 해결 불가. 권한은 group_permissions['%s']에 보관.",
					bindingKind, bindingName, sName, sName),
				map[string]any{
					"binding": bindingName,
					"group":   sName,
				})
			addPermissions(state.groupPermissions, sName, expanded)
		}

	default:
		state.warn(WUnknownSubjectKind,
			fmt.Sprintf("%s(%s) subject kind 알 수 없음: %q (name=%q)",
				bindingKind, bindingName, sKind, sName),
			map[string]any{
				"binding":      bindingName,
				"subject_kind": sKind,
				"subject_name": sName,
			})
	}
}

// resolveGroupToSAs — Python _resolve_group_to_sas 1:1.
// resolved=false 이면 호출자가 group_permissions 로 분기.
func resolveGroupToSAs(groupName string, nsToSAs map[string][]nsName, allSAs []nsName) ([]nsName, bool) {
	if groupName == "system:serviceaccounts" {
		return allSAs, true
	}
	const prefix = "system:serviceaccounts:"
	if strings.HasPrefix(groupName, prefix) {
		ns := groupName[len(prefix):]
		return nsToSAs[ns], true
	}
	return nil, false
}

// ----------------------------------------------------------------------------
// Entrypoint — Python extract() 1:1.
// ----------------------------------------------------------------------------

// Extract — snapshot dict 받아 direct_perm 산출 dict 반환.
//
// snapshot 필수 키: service_accounts, roles, cluster_roles, role_bindings, cluster_role_bindings.
// 누락 시 error. (3) 유연성 금지.
func Extract(snap map[string]any) (map[string]any, error) {
	required := []string{
		"service_accounts", "roles", "cluster_roles",
		"role_bindings", "cluster_role_bindings",
	}
	for _, k := range required {
		if _, ok := snap[k]; !ok {
			return nil, fmt.Errorf("snapshot missing required key: %s", k)
		}
	}

	saIndex := indexSAs(snap)
	roleIndex := indexRoles(snap)
	nsToSAs := groupSAsByNamespace(snap)

	// allSAs = sorted(saIndex)
	allSAs := make([]nsName, 0, len(saIndex))
	for k := range saIndex {
		allSAs = append(allSAs, k)
	}
	sort.Slice(allSAs, func(i, j int) bool {
		if allSAs[i].Namespace != allSAs[j].Namespace {
			return allSAs[i].Namespace < allSAs[j].Namespace
		}
		return allSAs[i].Name < allSAs[j].Name
	})

	state := &extractState{
		saPermissions:    map[string][]map[string]any{},
		groupPermissions: map[string][]map[string]any{},
		userPermissions:  map[string][]map[string]any{},
		warnings:         []map[string]any{},
	}

	rbs, _ := snap["role_bindings"].([]any)
	for _, e := range rbs {
		rb, _ := e.(map[string]any)
		if rb == nil {
			continue
		}
		processBinding(rb, "RoleBinding", roleIndex, saIndex, nsToSAs, allSAs, state)
	}
	crbs, _ := snap["cluster_role_bindings"].([]any)
	for _, e := range crbs {
		crb, _ := e.(map[string]any)
		if crb == nil {
			continue
		}
		processBinding(crb, "ClusterRoleBinding", roleIndex, saIndex, nsToSAs, allSAs, state)
	}

	capturedAt, _ := snap["captured_at"].(string)
	if capturedAt == "" {
		capturedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}

	// known_limitations 는 []string 으로 반환되지만 JSON 직렬화 시 []any 와 동일 모양.
	knownLim := make([]any, len(KnownLimitations))
	for i, s := range KnownLimitations {
		knownLim[i] = s
	}

	return map[string]any{
		"captured_at": capturedAt,
		"summary": map[string]any{
			"sa_count":      len(state.saPermissions),
			"group_count":   len(state.groupPermissions),
			"user_count":    len(state.userPermissions),
			"warning_count": len(state.warnings),
		},
		"sa_permissions":     toAnyMap(state.saPermissions),
		"group_permissions":  toAnyMap(state.groupPermissions),
		"user_permissions":   toAnyMap(state.userPermissions),
		"warnings":           toAnySlice(state.warnings),
		"known_limitations":  knownLim,
	}, nil
}

// toAnyMap / toAnySlice — fixpoint.InitialPermsFromDP 가 map[string]any / []any 를
// 기대하므로 동일 형식으로 통일.
func toAnyMap(m map[string][]map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		lst := make([]any, len(v))
		for i, e := range v {
			lst[i] = e
		}
		out[k] = lst
	}
	return out
}

func toAnySlice(s []map[string]any) []any {
	out := make([]any, len(s))
	for i, e := range s {
		out[i] = e
	}
	return out
}
