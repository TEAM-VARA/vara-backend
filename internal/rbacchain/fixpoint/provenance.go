// provenance.go — Python fixpoint/provenance.py 등가.
package fixpoint

import "github.com/vara/backend/internal/rbacchain/snapshot"

// MakeTransitionProvenance — Python make_transition_provenance() 1:1.
//
// dict 형식 (Python 과 동일 키):
//   kind            : "transition"
//   via_transition  : "R-INDIRECT-07" 등
//   triggering_sa   : "ns/name"
//   matched_perms   : [perm dict, ...]
//   absorbed_from_sa: "ns/name" (선택)
func MakeTransitionProvenance(
	viaTransition string,
	triggeringSA string,
	matchedPerms []Permission,
	absorbedFromSA string, // "" 이면 키 자체를 안 박음 (Python None 등가)
) map[string]any {
	mp := make([]map[string]any, len(matchedPerms))
	for i, p := range matchedPerms {
		mp[i] = permToDict(p)
	}
	prov := map[string]any{
		"kind":           "transition",
		"via_transition": viaTransition,
		"triggering_sa":  triggeringSA,
		"matched_perms":  mp,
	}
	if absorbedFromSA != "" {
		prov["absorbed_from_sa"] = absorbedFromSA
	}
	return prov
}

func permToDict(p Permission) map[string]any {
	return map[string]any{
		"api_group":        p.APIGroup,
		"resource":         p.Resource,
		"verb":             p.Verb,
		"namespace":        nullStringToAny(p.Namespace),
		"resource_name":    nullStringToAny(p.ResourceName),
		"non_resource_url": nullStringToAny(p.NonResourceURL),
	}
}

func nullStringToAny(n snapshot.NullString) any {
	if n.IsNull {
		return nil
	}
	return n.Value
}
