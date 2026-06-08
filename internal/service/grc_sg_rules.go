package service

import (
	"fmt"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// ─────────────────────────────────────────────
// AWS Security Group 기반 평가기 (account/region-global 스냅샷)
//
// 입력: snap.Related.SecurityGroups []map[string]any
//   각 SG : { group_id, group_name, vpc_id, description,
//             ingress_rules: []any, egress_rules: []any }
//   각 rule: { protocol:string, from_port:float64, to_port:float64, cidrs:[]any(string) }
//   (aws-reader/main.go mapRules 기준 — CIDR만 수집, source-SG 참조/태그는 미수집)
//
// 이 함수들은 모두 "승격(promoted)" 룰의 operator로 호출되므로 base.Matched 와
// base.Evidence["data_provided"] 만 채우면 finding_evaluator 의 승격 경로가
// NO_DATA / 미준수 / 준수 로 최종 verdict 를 확정한다. (Verdict 직접 설정 금지)
// ─────────────────────────────────────────────

// sgDefaultSensitivePorts: R-2.10.3-SG01(공개서버)이 전담하는 민감·관리 포트.
// R-2.6.1-SG01(영역 분리)은 이 포트들과 전체 포트 개방을 제외해 두 룰이 겹치지 않게 한다(중복 집계 방지).
var sgDefaultSensitivePorts = []int{22, 3389, 3306, 5432, 6379, 27017, 9200, 11211, 6443}

// sgInt coerces a JSON-decoded numeric (float64) into int.
func sgInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	}
	return 0
}

// sgList coerces a JSON-decoded value into []any.
func sgList(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// sgIntSlice reads an int slice from a condition param.
func sgIntSlice(cond map[string]any, key string) []int {
	arr, ok := cond[key].([]any)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, v := range arr {
		out = append(out, sgInt(v))
	}
	return out
}

// sgBool reads a bool condition param with a default.
func sgBool(cond map[string]any, key string, def bool) bool {
	if v, ok := cond[key].(bool); ok {
		return v
	}
	return def
}

// sgForbiddenCidrs builds the world-open CIDR set (default 0.0.0.0/0, ::/0).
func sgForbiddenCidrs(cond map[string]any) map[string]bool {
	list := condStringSlice(cond, "forbidden_cidrs")
	if len(list) == 0 {
		list = []string{"0.0.0.0/0", "::/0"}
	}
	m := make(map[string]bool, len(list))
	for _, c := range list {
		m[c] = true
	}
	return m
}

// sgRuleIsWorldOpen reports whether a single SG rule allows any world-open CIDR.
func sgRuleIsWorldOpen(rule map[string]any, forbidden map[string]bool) bool {
	for _, c := range sgList(rule["cidrs"]) {
		if forbidden[strVal(c)] {
			return true
		}
	}
	return false
}

// sgRulePortRange returns (from, to, allPorts). allPorts=true → 전체 프로토콜(-1)/전 포트.
func sgRulePortRange(rule map[string]any) (int, int, bool) {
	proto := strings.ToLower(strVal(rule["protocol"]))
	from := sgInt(rule["from_port"])
	to := sgInt(rule["to_port"])
	if proto == "-1" || proto == "all" || (from <= 0 && to >= 65535) {
		return 0, 65535, true
	}
	return from, to, false
}

// sgRuleCoversPort reports whether the rule's port range includes the given port.
func sgRuleCoversPort(rule map[string]any, port int) bool {
	from, to, all := sgRulePortRange(rule)
	if all {
		return true
	}
	return from <= port && port <= to
}

// sgPortLabel renders a human-readable port label.
func sgPortLabel(from, to int, all bool) string {
	switch {
	case all:
		return "전체 포트"
	case from == to:
		return fmt.Sprintf("포트 %d", from)
	default:
		return fmt.Sprintf("포트 %d-%d", from, to)
	}
}

// sgNoData builds a NO_DATA-bound result (data_provided=false → promoted 경로가 NO_DATA 처리).
func sgNoData(base grc.RuleResult, observation string, extra map[string]any) grc.RuleResult {
	base.Matched = false
	base.Observation = observation
	ev := map[string]any{"data_provided": false}
	for k, v := range extra {
		ev[k] = v
	}
	base.Evidence = ev
	return base
}

// ─────────────────────────────────────────────
// R-2.6.1-SG01: sg_world_open_ingress
// 0.0.0.0/0 인바운드가 허용 공개포트(기본 80/443) 외를 노출하면 위반(영역 분리/비인가 접근).
// ─────────────────────────────────────────────
func evalSGWorldOpenIngress(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	sgs := snap.Related.SecurityGroups
	if len(sgs) == 0 {
		return sgNoData(base, "Security Group 데이터 미수집 — 판단 불가", map[string]any{"sg_total": 0})
	}
	forbidden := sgForbiddenCidrs(cond)
	allowed := map[int]bool{}
	for _, p := range sgIntSlice(cond, "allowed_public_ports") {
		allowed[p] = true
	}
	if len(allowed) == 0 {
		allowed[80] = true
		allowed[443] = true
	}

	var violations []string
	for _, sg := range sgs {
		gid := strVal(sg["group_id"])
		gname := strVal(sg["group_name"])
		for _, ri := range sgList(sg["ingress_rules"]) {
			rule := toMap(ri)
			if rule == nil || !sgRuleIsWorldOpen(rule, forbidden) {
				continue
			}
			from, to, all := sgRulePortRange(rule)
			// 중복 방지: 전체 포트 개방과 민감·관리 포트 노출은 R-2.10.3-SG01이 전담하므로 제외
			if all {
				continue
			}
			ownedBy2103 := false
			for _, sp := range sgDefaultSensitivePorts {
				if sgRuleCoversPort(rule, sp) {
					ownedBy2103 = true
					break
				}
			}
			if ownedBy2103 {
				continue
			}
			// 남은 것: 민감하지 않은 특정/범위 포트의 광범위 노출 → 영역 분리 결함
			// 단일 허용 공개포트(80/443)만 노출하면 통과
			if from != to || !allowed[from] {
				violations = appendUnique(violations,
					fmt.Sprintf("%s(%s) 0.0.0.0/0 → %s", gid, gname, sgPortLabel(from, to, all)))
			}
		}
	}

	base.Matched = len(violations) > 0
	base.Evidence = map[string]any{
		"sg_total":        len(sgs),
		"violation_count": len(violations),
		"violations":      violations,
		"data_provided":   true,
	}
	if base.Matched {
		base.Observation = fmt.Sprintf("SG %d개 중 광범위(0.0.0.0/0) 인바운드 허용 %d건: %s",
			len(sgs), len(violations), strings.Join(violations, ", "))
	} else {
		base.Observation = fmt.Sprintf("SG %d개 모두 0.0.0.0/0 인바운드가 허용 공개포트 내로 제한됨", len(sgs))
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.10.3-SG01: sg_sensitive_port_world_open
// 0.0.0.0/0 인바운드가 관리·DB 등 민감 포트(또는 전체 포트)를 노출하면 위반(공개서버 강화).
// ─────────────────────────────────────────────
func evalSGSensitivePortWorldOpen(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	sgs := snap.Related.SecurityGroups
	if len(sgs) == 0 {
		return sgNoData(base, "Security Group 데이터 미수집 — 판단 불가", map[string]any{"sg_total": 0})
	}
	forbidden := sgForbiddenCidrs(cond)
	sensitive := sgIntSlice(cond, "sensitive_ports")
	if len(sensitive) == 0 {
		sensitive = sgDefaultSensitivePorts
	}
	flagAll := sgBool(cond, "flag_all_ports", true)

	var violations []string
	for _, sg := range sgs {
		gid := strVal(sg["group_id"])
		gname := strVal(sg["group_name"])
		for _, ri := range sgList(sg["ingress_rules"]) {
			rule := toMap(ri)
			if rule == nil || !sgRuleIsWorldOpen(rule, forbidden) {
				continue
			}
			_, _, all := sgRulePortRange(rule)
			if all {
				if flagAll {
					violations = appendUnique(violations, fmt.Sprintf("%s(%s) 0.0.0.0/0 → 전체 포트", gid, gname))
				}
				continue
			}
			for _, sp := range sensitive {
				if sgRuleCoversPort(rule, sp) {
					violations = appendUnique(violations, fmt.Sprintf("%s(%s) 0.0.0.0/0 → 포트 %d", gid, gname, sp))
				}
			}
		}
	}

	base.Matched = len(violations) > 0
	base.Evidence = map[string]any{
		"sg_total":        len(sgs),
		"violation_count": len(violations),
		"violations":      violations,
		"data_provided":   true,
	}
	if base.Matched {
		base.Observation = fmt.Sprintf("SG %d개 중 민감·관리 포트 외부 노출 %d건: %s",
			len(sgs), len(violations), strings.Join(violations, ", "))
	} else {
		base.Observation = fmt.Sprintf("SG %d개에서 민감·관리 포트의 0.0.0.0/0 노출 없음", len(sgs))
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.6.7-SG01: sg_unrestricted_egress
// egress 0.0.0.0/0 전체 개방 = 아웃바운드 미통제(인터넷 자유 접속). 기본은 전체 포트 개방만 위반.
// ─────────────────────────────────────────────
func evalSGUnrestrictedEgress(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	sgs := snap.Related.SecurityGroups
	if len(sgs) == 0 {
		return sgNoData(base, "Security Group 데이터 미수집 — 판단 불가", map[string]any{"sg_total": 0})
	}
	forbidden := sgForbiddenCidrs(cond)
	allOnly := sgBool(cond, "match_all_ports_only", true)

	var violations []string
	for _, sg := range sgs {
		gid := strVal(sg["group_id"])
		gname := strVal(sg["group_name"])
		for _, re := range sgList(sg["egress_rules"]) {
			rule := toMap(re)
			if rule == nil || !sgRuleIsWorldOpen(rule, forbidden) {
				continue
			}
			from, to, all := sgRulePortRange(rule)
			if allOnly && !all {
				continue // 포트가 제한된 egress는 통제된 것으로 본다
			}
			violations = appendUnique(violations,
				fmt.Sprintf("%s(%s) egress 0.0.0.0/0 → %s", gid, gname, sgPortLabel(from, to, all)))
		}
	}

	base.Matched = len(violations) > 0
	base.Evidence = map[string]any{
		"sg_total":        len(sgs),
		"violation_count": len(violations),
		"violations":      violations,
		"data_provided":   true,
	}
	if base.Matched {
		base.Observation = fmt.Sprintf("SG %d개 중 아웃바운드 전체 개방 %d건: %s",
			len(sgs), len(violations), strings.Join(violations, ", "))
	} else {
		base.Observation = fmt.Sprintf("SG %d개 모두 egress가 목적지/포트로 제한됨", len(sgs))
	}
	return base
}

// ─────────────────────────────────────────────
// R-2.8.3-SG01: sg_cross_env_ingress
// 운영↔개발 SG 간 인바운드 허용 여부. 현재 aws-reader는 CIDR만 수집하고
// SG 간 참조(UserIdGroupPairs)·서브넷/계정 env 매핑을 수집하지 않으므로 판별 불가 → NO_DATA.
// (활성화하려면 agent mapRules에 UserIdGroupPairs + SG 태그(env) 수집을 추가해야 함)
// ─────────────────────────────────────────────
func evalSGCrossEnvIngress(base grc.RuleResult, snap *ClusterSnapshot, cond map[string]any) grc.RuleResult {
	_ = cond
	return sgNoData(base,
		"환경 간(운영↔개발) SG 통신 판별 불가 — 현재 수집 데이터에 SG 간 참조(UserIdGroupPairs)와 서브넷/계정 env 매핑이 없음(aws-reader가 CIDR만 수집).",
		map[string]any{
			"sg_total": len(snap.Related.SecurityGroups),
			"reason":   "source_sg_refs_and_env_mapping_not_collected",
		})
}
