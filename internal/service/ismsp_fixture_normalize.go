package service

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NormalizeRuleFixtureEvidence derives flat boolean/numeric fields expected by structured_match
// rules from the ISMS-P JSON fixture "data" objects (EKS audit, Kyverno, ArgoCD, eBPF DNS, …).
func NormalizeRuleFixtureEvidence(rulesetRuleID string, m map[string]any) {
	switch rulesetRuleID {
	case "2.2.1-R007":
		normalize22107(m)
	case "2.2.5-R003":
		normalize22503(m)
	case "2.2.5-R005":
		normalize22505(m)
	case "1.3.1-R002":
		normalize13102(m)
	case "2.2.6-R004":
		normalize22604(m)
	case "1.2.1-R002":
		normalize12102(m)
	case "1.1.4-R011":
		normalize11411(m)
	case "1.1.4-R012":
		normalize11412(m)
	case "1.2.3-R004":
		normalize12304(m)
	case "1.3.1-R003":
		normalize13103(m)
	case "2.2.1-R002":
		normalize22102(m)
	case "2.2.2-R006":
		normalize22206(m)
	case "2.2.2-R009":
		normalize22209(m)
	default:
		return
	}
}

func normalize22107(m map[string]any) {
	lt, _ := m["log_types"].([]any)
	have := map[string]bool{}
	for _, x := range lt {
		have[strings.ToLower(strings.TrimSpace(fmt.Sprint(x)))] = true
	}
	m["required_eks_audit_log_types_present"] = have["api"] && have["audit"] && have["authenticator"]
	dash := m["dashboard_url"]
	ok := false
	switch v := dash.(type) {
	case string:
		ok = strings.TrimSpace(v) != ""
	case nil:
		ok = false
	default:
		s := strings.TrimSpace(fmt.Sprint(v))
		ok = s != "" && s != "<nil>"
	}
	m["dashboard_configured"] = ok
}

func normalize22503(m map[string]any) {
	tts := m["time_to_full_revocation_sec"]
	met := false
	if f, ok := floatFromAny(tts); ok && f >= 0 && f <= 300 {
		met = true
	}
	m["revocation_sla_met"] = met
	if arr, ok := m["remaining_rolebindings_for_user"].([]any); ok {
		m["no_remaining_rolebindings"] = len(arr) == 0
	} else {
		m["no_remaining_rolebindings"] = true
	}
}

func normalize22505(m map[string]any) {
	events, _ := m["audit_events"].([]any)
	del, crt := false, false
	for _, e := range events {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(fmt.Sprint(em["verb"]), "delete") {
			del = true
		}
		if strings.EqualFold(fmt.Sprint(em["verb"]), "create") {
			crt = true
		}
	}
	m["job_change_audit_delete_present"] = del
	m["job_change_audit_create_present"] = crt
	if arr, ok := m["old_permissions_still_active"].([]any); ok {
		m["old_permissions_cleared"] = len(arr) == 0
	} else {
		m["old_permissions_cleared"] = true
	}
}

func normalize13102(m map[string]any) {
	apps, ok := m["argocd_apps"].([]any)
	if !ok {
		m["all_argocd_apps_synced_healthy"] = false
		return
	}
	allOK := true
	for _, a := range apps {
		am, ok := a.(map[string]any)
		if !ok {
			allOK = false
			break
		}
		sync := strings.TrimSpace(fmt.Sprint(am["sync"]))
		health := strings.TrimSpace(fmt.Sprint(am["health"]))
		if sync != "Synced" || health != "Healthy" {
			allOK = false
			break
		}
	}
	m["all_argocd_apps_synced_healthy"] = allOK
}

func normalize22604(m map[string]any) {
	ec, ok := m["evidence_collected"].(map[string]any)
	if !ok {
		m["all_evidence_channels_present"] = false
		return
	}
	keys := []string{
		"audit_log_export", "cloudtrail_export", "vpc_flow_export",
		"falco_alerts", "ebpf_process_events",
	}
	all := true
	for _, k := range keys {
		v := ec[k]
		if v == nil {
			all = false
			break
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" || s == "<nil>" {
			all = false
			break
		}
	}
	m["all_evidence_channels_present"] = all
}

func normalize12102(m map[string]any) {
	md, _ := m["missing_in_definition"].([]any)
	mi, _ := m["missing_in_inventory"].([]any)
	m["asset_inventory_diff_clean"] = len(md) == 0 && len(mi) == 0
}

func normalize11411(m map[string]any) {
	c := -1
	switch v := m["unauthorized_count"].(type) {
	case float64:
		c = int(v)
	case int:
		c = v
	case int64:
		c = int(v)
	case json.Number:
		i, err := v.Int64()
		if err == nil {
			c = int(i)
		}
	}
	if c < 0 {
		c = 999
	}
	m["shadow_it_dns_policy_ok"] = c == 0
}

func normalize11412(m map[string]any) {
	cp, ok := m["clusterpolicy"].(map[string]any)
	if !ok {
		m["isms_scope_tagging_ok"] = false
		return
	}
	spec, _ := cp["spec"].(map[string]any)
	action := strings.ToLower(strings.TrimSpace(fmt.Sprint(spec["validationFailureAction"])))
	enforce := action == "enforce"
	pr, _ := m["policyreport_summary"].(map[string]any)
	failN := 999.0
	if v, ok := pr["fail"]; ok {
		if f, ok := floatFromAny(v); ok {
			failN = f
		}
	}
	m["isms_scope_tagging_ok"] = enforce && failN == 0
}

// normalize12304 derives vuln_scan_clean for 1.2.3-R004 (기술적 취약점 식별).
// pass if inspector_findings.CRITICAL == 0 AND kube_bench_score >= 90 AND falco_runtime_alerts_24h == 0
func normalize12304(m map[string]any) {
	clean := true
	if findings, ok := m["inspector_findings"].(map[string]any); ok {
		if crit, ok := floatFromAny(findings["CRITICAL"]); !ok || crit > 0 {
			clean = false
		}
	} else {
		clean = false
	}
	if score, ok := floatFromAny(m["kube_bench_score"]); !ok || score < 90 {
		clean = false
	}
	if alerts, ok := floatFromAny(m["falco_runtime_alerts_24h"]); !ok || alerts > 0 {
		clean = false
	}
	m["vuln_scan_clean"] = clean
}

// normalize13103 derives implementation_verified for 1.3.1-R003 (구현 검증).
// pass if policyreport_summary.fail == 0 AND recent_admission_denies count > 0 AND policy_mode != "audit"
func normalize13103(m map[string]any) {
	ok := true
	if pr, prOK := m["policyreport_summary"].(map[string]any); prOK {
		if f, fOK := floatFromAny(pr["fail"]); !fOK || f > 0 {
			ok = false
		}
	} else {
		ok = false
	}
	if denies, dOK := m["recent_admission_denies"].([]any); !dOK || len(denies) == 0 {
		ok = false
	}
	if mode, mOK := m["policy_mode"].(string); mOK && strings.EqualFold(mode, "audit") {
		ok = false
	}
	m["implementation_verified"] = ok
}

// normalize22102 derives key_personnel_group_managed for 2.2.1-R002 (주요 직무자 명부).
// pass if rolebindings_for_group non-empty AND individual_rolebindings_with_admin nil/empty
func normalize22102(m map[string]any) {
	groupBindings, _ := m["rolebindings_for_group"].([]any)
	individualBindings, _ := m["individual_rolebindings_with_admin"].([]any)
	m["key_personnel_group_managed"] = len(groupBindings) > 0 && len(individualBindings) == 0
}

// normalize22206 derives sod_policy_enforced for 2.2.2-R006 (권한 충돌 점검).
// pass if kyverno_sod_policy.mode == "enforce" AND sod_violations_currently_active == 0
func normalize22206(m map[string]any) {
	ok := true
	if policy, pOK := m["kyverno_sod_policy"].(map[string]any); pOK {
		mode := strings.TrimSpace(fmt.Sprint(policy["mode"]))
		if !strings.EqualFold(mode, "enforce") {
			ok = false
		}
	} else {
		ok = false
	}
	if v, vOK := floatFromAny(m["sod_violations_currently_active"]); !vOK || v > 0 {
		ok = false
	}
	m["sod_policy_enforced"] = ok
}

// normalize22209 derives sod_review_current for 2.2.2-R009 (직무 분리 정기 점검).
// pass if review_frequency_per_month >= 1 AND review_report_path is non-nil/non-empty
func normalize22209(m map[string]any) {
	ok := true
	if freq, fOK := floatFromAny(m["review_frequency_per_month"]); !fOK || freq < 1 {
		ok = false
	}
	switch rp := m["review_report_path"].(type) {
	case string:
		if strings.TrimSpace(rp) == "" {
			ok = false
		}
	case nil:
		ok = false
	}
	m["sod_review_current"] = ok
}

func floatFromAny(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case nil:
		return 0, false
	default:
		return 0, false
	}
}
