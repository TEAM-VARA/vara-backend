// Package fixpoint - Python fixpoint/ 패키지 1:1 직역.
//
// permissions.go — Python fixpoint/permissions.py 등가.
//   Permission, PermissionSet, covers(), evaluate_rule.
package fixpoint

import (
	"fmt"
	"strings"

	"github.com/vara/backend/internal/rbacchain/snapshot"
)

// _RESOURCENAME_IGNORED_VERBS — 인가 시점에 resourceNames를 무시하는 verb (top-level만).
// 출처: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources
var resourceNameIgnoredVerbs = map[string]struct{}{
	"create":           {},
	"deletecollection": {},
}

// Permission 타입 별칭 — 호출 편의용.
type Permission = snapshot.Permission

// ClusterAdmin — (*,*,*,None,None,None). Python 의 CLUSTER_ADMIN 등가.
var ClusterAdmin = Permission{
	APIGroup:       "*",
	Resource:       "*",
	Verb:           "*",
	Namespace:      snapshot.Null(),
	ResourceName:   snapshot.Null(),
	NonResourceURL: snapshot.Null(),
}

// ----------------------------------------------------------------------------
// covers() — Permission 의 partial order. Python Permission.covers() 1:1.
// ----------------------------------------------------------------------------

// Covers — self 가 other 를 의미상 포함하는가.
func Covers(self, other Permission) bool {
	if self.NonResourceURL.IsNull != other.NonResourceURL.IsNull {
		return false
	}
	if !self.NonResourceURL.IsNull {
		return nonResourceURLCovers(self.NonResourceURL.Value, other.NonResourceURL.Value) &&
			verbCovers(self.Verb, other.Verb)
	}
	return apiGroupCovers(self.APIGroup, other.APIGroup) &&
		resourceCovers(self.Resource, other.Resource) &&
		verbCovers(self.Verb, other.Verb) &&
		namespaceCovers(self.Namespace, other.Namespace) &&
		resourceNameCovers(self.ResourceName, other.ResourceName, self.Verb, self.Resource)
}

func apiGroupCovers(a, b string) bool { return a == "*" || a == b }
func resourceCovers(a, b string) bool { return a == "*" || a == b }
func verbCovers(a, b string) bool     { return a == "*" || a == b }

func namespaceCovers(a, b snapshot.NullString) bool {
	if a.IsNull {
		return true
	}
	return !b.IsNull && a.Value == b.Value
}

func resourceNameCovers(selfN, otherN snapshot.NullString, verb, resource string) bool {
	// "/" not in resource and verb in IGNORED → return True
	if !strings.Contains(resource, "/") {
		if _, ok := resourceNameIgnoredVerbs[verb]; ok {
			return true
		}
	}
	if selfN.IsNull {
		return true
	}
	if otherN.IsNull {
		return false
	}
	return selfN.Value == otherN.Value
}

func nonResourceURLCovers(selfU, otherU string) bool {
	if strings.HasSuffix(selfU, "/*") {
		return strings.HasPrefix(otherU, selfU[:len(selfU)-1])
	}
	return selfU == otherU
}

// ----------------------------------------------------------------------------
// permissions_intersect — evaluate_rule 용 대칭 교집합 검사.
// Python permissions_intersect() 1:1.
// ----------------------------------------------------------------------------

func PermissionsIntersect(p1, p2 Permission) bool {
	if p1.NonResourceURL.IsNull != p2.NonResourceURL.IsNull {
		return false
	}
	if !p1.NonResourceURL.IsNull {
		return nonResourceURLIntersect(p1.NonResourceURL.Value, p2.NonResourceURL.Value) &&
			(p1.Verb == "*" || p2.Verb == "*" || p1.Verb == p2.Verb)
	}
	if !(p1.APIGroup == "*" || p2.APIGroup == "*" || p1.APIGroup == p2.APIGroup) {
		return false
	}
	if !(p1.Resource == "*" || p2.Resource == "*" || p1.Resource == p2.Resource) {
		return false
	}
	if !(p1.Verb == "*" || p2.Verb == "*" || p1.Verb == p2.Verb) {
		return false
	}
	if !(p1.Namespace.IsNull || p2.Namespace.IsNull || p1.Namespace.Value == p2.Namespace.Value) {
		return false
	}
	return true
}

func nonResourceURLIntersect(u1, u2 string) bool {
	if strings.HasSuffix(u1, "/*") {
		return strings.HasPrefix(u2, u1[:len(u1)-1])
	}
	if strings.HasSuffix(u2, "/*") {
		return strings.HasPrefix(u1, u2[:len(u2)-1])
	}
	return u1 == u2
}

// ----------------------------------------------------------------------------
// PermissionSet — Python class PermissionSet 1:1.
//
// 내부 표현은 list[Permission] + cover-aware add. 비커버 권한만 보존.
// ----------------------------------------------------------------------------

type PermissionSet struct {
	perms []Permission
}

func NewPermissionSet() *PermissionSet {
	return &PermissionSet{}
}

// Len — len(ps).
func (ps *PermissionSet) Len() int { return len(ps.perms) }

// Iter — Go 에는 iterator 가 없으니 slice 사본 반환.
// Python `for perm in ps:` 등가 — 순서는 삽입 순서.
func (ps *PermissionSet) Iter() []Permission {
	out := make([]Permission, len(ps.perms))
	copy(out, ps.perms)
	return out
}

// Contains — Python `perm in ps` 등가. cover-aware.
func (ps *PermissionSet) Contains(perm Permission) bool {
	for _, existing := range ps.perms {
		if Covers(existing, perm) {
			return true
		}
	}
	return false
}

// Add — Python ps.add(perm). 이미 cover 되면 false, 추가하면 true.
func (ps *PermissionSet) Add(perm Permission) bool {
	if ps.Contains(perm) {
		return false
	}
	ps.perms = append(ps.perms, perm)
	return true
}

// ----------------------------------------------------------------------------
// evaluate_rule — 룰 dict 평가. Python evaluate_rule() 1:1.
// 룰 dict 는 yaml.safe_load 결과(map[string]any) 가정.
// ----------------------------------------------------------------------------

// EvaluateRule — Python evaluate_rule().
// 반환: list of list. 각 inner list 는 한 매치의 매칭된 perm들(match_all_of cross product의 한 조합).
func EvaluateRule(rule map[string]any, saPerms *PermissionSet) ([][]Permission, error) {
	_, hasAny := rule["match_any_of"]
	_, hasAll := rule["match_all_of"]
	if hasAny && hasAll {
		return nil, fmt.Errorf("Rule %v: match_any_of와 match_all_of 동시 사용 금지", ruleID(rule))
	}
	if !hasAny && !hasAll {
		return nil, fmt.Errorf("Rule %v: match_any_of 또는 match_all_of 필요", ruleID(rule))
	}
	if hasAny {
		triples, err := asListOfDict(rule["match_any_of"])
		if err != nil {
			return nil, fmt.Errorf("Rule %v: match_any_of 형식 오류: %w", ruleID(rule), err)
		}
		return evaluateAnyOf(triples, saPerms)
	}
	items, err := asListOfDict(rule["match_all_of"])
	if err != nil {
		return nil, fmt.Errorf("Rule %v: match_all_of 형식 오류: %w", ruleID(rule), err)
	}
	return evaluateAllOf(items, saPerms)
}

func ruleID(rule map[string]any) any {
	if v, ok := rule["id"]; ok {
		return v
	}
	return "?"
}

func asListOfDict(v any) ([]map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	lst, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", v)
	}
	out := make([]map[string]any, 0, len(lst))
	for _, e := range lst {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected dict, got %T", e)
		}
		out = append(out, m)
	}
	return out, nil
}

// _triple_matches — 룰의 단일 triple (+필터) 가 perm 과 매치하는가.
func tripleMatches(triple map[string]any, perm Permission) (bool, error) {
	// CRITICAL: 모든 NullString 필드를 명시적으로 Null() 로 채워야 한다.
	// NullString zero value 는 {Value:"", IsNull:false} 인데 PermissionsIntersect
	// 첫 줄이 IsNull 일치 비교라 NonResourceURL 누락하면 매치가 항상 false 가 된다.
	// Python 의 default None 등가를 명시적으로 줘야 동작.
	rulePerm := Permission{
		APIGroup:       getStringFromMap(triple, "api_group"),
		Resource:       getStringFromMap(triple, "resource"),
		Verb:           getStringFromMap(triple, "verb"),
		Namespace:      snapshot.Null(),
		ResourceName:   snapshot.Null(),
		NonResourceURL: snapshot.Null(),
	}
	if !PermissionsIntersect(rulePerm, perm) {
		return false, nil
	}

	// filter resource_names
	if filterNames, ok := triple["resource_names"]; ok && filterNames != nil {
		names, err := asStringList(filterNames)
		if err != nil {
			return false, fmt.Errorf("resource_names: %w", err)
		}
		if len(names) > 0 {
			if !perm.ResourceName.IsNull {
				if !contains(names, perm.ResourceName.Value) {
					return false, nil
				}
			}
		}
	}

	// filter within_namespaces
	if filterNs, ok := triple["within_namespaces"]; ok && filterNs != nil {
		nss, err := asStringList(filterNs)
		if err != nil {
			return false, fmt.Errorf("within_namespaces: %w", err)
		}
		if len(nss) > 0 {
			if !perm.Namespace.IsNull {
				if !contains(nss, perm.Namespace.Value) {
					return false, nil
				}
			}
		}
	}

	if v, ok := triple["from_cluster_wide"]; ok && v != nil {
		// Python raises NotImplementedError. Go 도 동일.
		if b, _ := v.(bool); b {
			return false, fmt.Errorf("from_cluster_wide 필터는 아직 구현 안 됨")
		}
	}

	return true, nil
}

func getStringFromMap(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func asStringList(v any) ([]string, error) {
	lst, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", v)
	}
	out := make([]string, 0, len(lst))
	for _, e := range lst {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", e)
		}
		out = append(out, s)
	}
	return out, nil
}

func contains(lst []string, s string) bool {
	for _, x := range lst {
		if x == s {
			return true
		}
	}
	return false
}

func evaluateAnyOf(triples []map[string]any, saPerms *PermissionSet) ([][]Permission, error) {
	var matches [][]Permission
	for _, triple := range triples {
		for _, perm := range saPerms.Iter() {
			ok, err := tripleMatches(triple, perm)
			if err != nil {
				return nil, err
			}
			if ok {
				matches = append(matches, []Permission{perm})
			}
		}
	}
	return matches, nil
}

func evaluateAllOf(items []map[string]any, saPerms *PermissionSet) ([][]Permission, error) {
	var perItemMatches [][]Permission
	for _, item := range items {
		var innerTriples []map[string]any
		if inner, ok := item["match_any_of"]; ok {
			t, err := asListOfDict(inner)
			if err != nil {
				return nil, err
			}
			innerTriples = t
		} else {
			innerTriples = []map[string]any{item}
		}

		var itemMatches []Permission
		for _, triple := range innerTriples {
			for _, perm := range saPerms.Iter() {
				ok, err := tripleMatches(triple, perm)
				if err != nil {
					return nil, err
				}
				if ok && !containsPerm(itemMatches, perm) {
					itemMatches = append(itemMatches, perm)
				}
			}
		}
		if len(itemMatches) == 0 {
			return nil, nil
		}
		perItemMatches = append(perItemMatches, itemMatches)
	}

	// cross product (Python itertools.product)
	return cartesianProduct(perItemMatches), nil
}

func containsPerm(lst []Permission, p Permission) bool {
	for _, x := range lst {
		if x == p {
			return true
		}
	}
	return false
}

// cartesianProduct — Python itertools.product 등가.
// 입력 [[a,b], [c,d]] → [[a,c], [a,d], [b,c], [b,d]].
func cartesianProduct(lists [][]Permission) [][]Permission {
	if len(lists) == 0 {
		return nil
	}
	out := [][]Permission{{}}
	for _, lst := range lists {
		var next [][]Permission
		for _, prefix := range out {
			for _, p := range lst {
				combo := make([]Permission, len(prefix)+1)
				copy(combo, prefix)
				combo[len(prefix)] = p
				next = append(next, combo)
			}
		}
		out = next
	}
	return out
}
