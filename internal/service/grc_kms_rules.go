package service

import (
	"fmt"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// ─────────────────────────────────────────────
// AWS KMS 키 기반 평가기 (account/region-global 스냅샷)
//
// 입력: snap.Related.KmsKeys []map[string]any  (aws-reader → aws_kms_keys)
//   각 키 : { key_id, arn, key_state, key_manager, key_spec,
//             enabled(bool), rotation_enabled(bool) }
//
// R-2.7.1-04: kms_key_rotation
//   고객 관리형 키(CMK)가 활성(Enabled) + 자동 로테이션 + 승인 알고리즘을 모두
//   충족하면 준수. 하나라도 미충족이면 미준수. CMK가 없으면 점검 대상 부재(NO_DATA),
//   키 데이터 자체가 없으면(미수집) NO_DATA.
//
//   이 함수는 "승격(promoted)" 룰 operator로 호출되므로 base.Matched 와
//   base.Evidence["data_provided"] 만 채우고, 최종 Verdict 는 finding_evaluator 가
//   확정한다. (Verdict 직접 설정 금지 — SG/CloudTrail 평가기와 동일 규약)
// ─────────────────────────────────────────────
func evalKmsKeyRotation(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	keys := snap.Related.KmsKeys
	if len(keys) == 0 {
		return sgNoData(base, "KMS 키 데이터 미수집 — 키 로테이션·상태 판단 불가", map[string]any{"key_total": 0})
	}

	reqRotation := sgBool(cond, "require_rotation", true)
	reqEnabled := sgBool(cond, "require_enabled", true)

	approved := map[string]bool{}
	if arr, ok := cond["approved_key_specs"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				approved[s] = true
			}
		}
	}
	if len(approved) == 0 {
		approved = map[string]bool{
			"SYMMETRIC_DEFAULT": true, "RSA_2048": true, "RSA_3072": true, "RSA_4096": true,
		}
	}

	cmkTotal := 0
	var issues []string
	for _, k := range keys {
		// AWS 관리형 키는 자동 로테이션 대상이라 점검에서 제외, 고객 관리형(CMK)만 평가
		if !strings.EqualFold(strVal(k["key_manager"]), "CUSTOMER") {
			continue
		}
		cmkTotal++
		var miss []string
		if reqEnabled && (k["enabled"] != true || strVal(k["key_state"]) != "Enabled") {
			miss = append(miss, "비활성/사용불가")
		}
		if reqRotation && k["rotation_enabled"] != true {
			miss = append(miss, "자동 로테이션 미설정")
		}
		if spec := strVal(k["key_spec"]); spec != "" && !approved[spec] {
			miss = append(miss, "비승인 알고리즘("+spec+")")
		}
		if len(miss) > 0 {
			issues = appendUnique(issues, fmt.Sprintf("%s: %s", strVal(k["key_id"]), strings.Join(miss, ", ")))
		}
	}

	if cmkTotal == 0 {
		return sgNoData(base, "고객 관리형 KMS 키(CMK) 없음 — 점검 대상 부재", map[string]any{"key_total": len(keys), "cmk_total": 0})
	}

	if len(issues) == 0 {
		base.Matched = false
		base.Observation = fmt.Sprintf("고객 관리형 KMS 키 %d개 모두 활성·자동 로테이션·승인 알고리즘 충족", cmkTotal)
		base.Evidence = map[string]any{"key_total": len(keys), "cmk_total": cmkTotal, "data_provided": true}
		return base
	}

	base.Matched = true
	base.Observation = "KMS 키 로테이션·상태 미충족: " + strings.Join(issues, " / ")
	base.Evidence = map[string]any{
		"key_total":     len(keys),
		"cmk_total":     cmkTotal,
		"issues":        issues,
		"data_provided": true,
	}
	return base
}
