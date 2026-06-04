// escalation.go — 적재용 출력 헬퍼.
//
// DumpOutputs(파일) 대신, 서비스가 결과를 DB 로 바로 넣을 수 있도록
// 메모리 형태의 산출물을 만든다. buildAllPerms/buildDelta(dump.go) 와 동일한
// 기준을 재사용하므로 CLI 파일 경로와 동치.
package fixpoint

import (
	"encoding/json"

	"github.com/vara/backend/internal/rbacchain/snapshot"
)

// EscalationRecord — fixpoint 으로 "새로 흡수된" 권한 한 건 (transition provenance 별).
type EscalationRecord struct {
	SA             snapshot.SAKey
	Perm           Permission
	PermRepr       string
	ViaTransition  string
	AbsorbedFromSA string // "" 가능 (Python None 등가)
}

// NewlyAbsorbedRecords — buildDelta 와 동일한 "newly absorbed" 기준으로
// (SA, 권한, transition) 레코드를 평탄화해 반환. rbac_escalation_paths 적재용.
//
// 기준 (buildDelta 1:1):
//   - newly absorbed = allPerms 엔 있으나 initialPerms 에 (객체 ==) 없던 perm
//   - 그 perm 의 provenance 중 kind=="transition" 인 것만, transition 1건당 1행
func NewlyAbsorbedRecords(
	allPerms map[snapshot.SAKey]*PermissionSet,
	initialPerms map[snapshot.SAKey]*PermissionSet,
	provenance ProvenanceIndex,
) []EscalationRecord {
	var out []EscalationRecord
	for _, sa := range sortedSAKeys(allPerms) {
		ps := allPerms[sa]
		initial := initialPerms[sa]
		initialSet := map[Permission]struct{}{}
		if initial != nil {
			for _, p := range initial.Iter() {
				initialSet[p] = struct{}{}
			}
		}
		for _, perm := range ps.Iter() {
			if _, ok := initialSet[perm]; ok {
				continue // 기존 직접 권한 → escalation 아님
			}
			var provList []map[string]any
			if provenance[sa] != nil {
				provList = provenance[sa][perm]
			}
			for _, pr := range provList {
				if k, _ := pr["kind"].(string); k != "transition" {
					continue
				}
				via, _ := pr["via_transition"].(string)
				absorbed, _ := pr["absorbed_from_sa"].(string)
				out = append(out, EscalationRecord{
					SA:             sa,
					Perm:           perm,
					PermRepr:       permRepr(perm),
					ViaTransition:  via,
					AbsorbedFromSA: absorbed,
				})
			}
		}
	}
	return out
}

// BuildReportInputs — sareport.Build 에 넘길 (all_perms, delta) 를 파일 없이 메모리로.
//
// DumpOutputs 와 동일한 buildAllPerms/buildDelta 를 거친 뒤 JSON 라운드트립으로
// map[string]any(=파일에서 읽은 것과 동일 형태)로 변환 → CLI 경로와 동치.
func BuildReportInputs(
	allPerms map[snapshot.SAKey]*PermissionSet,
	initialPerms map[snapshot.SAKey]*PermissionSet,
	provenance ProvenanceIndex,
) (allPermsObj map[string]any, deltaObj map[string]any, err error) {
	if err = jsonRoundTrip(buildAllPerms(allPerms), &allPermsObj); err != nil {
		return nil, nil, err
	}
	if err = jsonRoundTrip(buildDelta(allPerms, initialPerms, provenance), &deltaObj); err != nil {
		return nil, nil, err
	}
	return allPermsObj, deltaObj, nil
}

func jsonRoundTrip(in any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
