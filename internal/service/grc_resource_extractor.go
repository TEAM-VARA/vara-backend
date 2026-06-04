package service

import (
	"fmt"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// ExtractViolatedResources inspects raw evidence data and returns per-resource
// violations with K8sSource populated. Returns nil if no extractor is registered
// for the given ruleID (caller should keep generic violations).
func ExtractViolatedResources(ruleID string, evidenceData []any) []grc.Violation {
	fn, ok := resourceExtractors[ruleID]
	if !ok {
		return nil
	}
	// Merge all evidence maps into one for the extractor.
	merged := make(map[string]any)
	for _, d := range evidenceData {
		if m, ok := d.(map[string]any); ok {
			for k, v := range m {
				merged[k] = v
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return fn(merged)
}

// extractorFunc takes merged raw evidence data and returns per-resource violations.
type extractorFunc func(data map[string]any) []grc.Violation

var resourceExtractors = map[string]extractorFunc{
	// 1.1.4
	"1.1.4-R007": extractNsScopeViolations,
	"1.1.4-R011": extractDNSViolations,
	"1.1.4-R012": extractKyvernoViolations,
	// 1.3.1
	"1.3.1-R007": extractPolicyChangeViolations,
	// 2.2.1
	"2.2.1-R002": extractIndividualRBViolations,
	"2.2.1-R007": extractAuditLogViolations,
	// 2.2.2
	"2.2.2-R002": extractAuditEventViolations,
	"2.2.2-R003": extractOverlapUserViolations,
	"2.2.2-R006": extractSoDViolations,
	"2.2.2-R008": extractSelfMergePRViolations,
	// 2.2.5
	"2.2.5-R003": extractRemainingRBViolations,
	"2.2.5-R005": extractOldPermViolations,
	"2.2.5-R009": extractOrphanedAccountViolations,
	"2.2.5-R010": extractPostTermEventViolations,
}

// ── helpers ──

func toSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func str(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func boolVal(m map[string]any, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	switch b := v.(type) {
	case bool:
		return b, true
	}
	return false, false
}

// ── 1.1.4-R007: namespace scope label 누락 ──

func extractNsScopeViolations(data map[string]any) []grc.Violation {
	items := toSlice(data["items"])
	if len(items) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, item := range items {
		m := toMap(item)
		if m == nil {
			continue
		}
		meta := toMap(m["metadata"])
		if meta == nil {
			continue
		}
		nsName := str(meta, "name")
		labels := toMap(meta["labels"])
		scope := ""
		if labels != nil {
			scope = str(labels, "isms-p/scope")
		}
		if scope == "" {
			violations = append(violations, grc.Violation{
				Field:       "isms-p/scope",
				Expected:    "in-scope | out-of-scope",
				Actual:      nil,
				Description: fmt.Sprintf("Namespace '%s'에 isms-p/scope 라벨 누락", nsName),
				Severity:    "high",
				K8sSource: grc.K8sSource{
					Namespace:    nsName,
					ResourceKind: "Namespace",
					ResourceName: nsName,
				},
			})
		}
	}
	return violations
}

// ── 1.1.4-R011: 비인가 DNS 쿼리 ──

func extractDNSViolations(data map[string]any) []grc.Violation {
	events := toSlice(data["dns_events_last_24h"])
	if len(events) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, ev := range events {
		m := toMap(ev)
		if m == nil {
			continue
		}
		authorized, ok := boolVal(m, "authorized")
		if ok && !authorized {
			violations = append(violations, grc.Violation{
				Field:       "authorized",
				Expected:    "true",
				Actual:      false,
				Description: fmt.Sprintf("비인가 DNS 쿼리: %s → %s", str(m, "pod"), str(m, "query")),
				Severity:    "high",
				K8sSource: grc.K8sSource{
					Namespace:    str(m, "namespace"),
					ResourceKind: "Pod",
					ResourceName: str(m, "pod"),
				},
			})
		}
	}
	return violations
}

// ── 1.1.4-R012: Kyverno PolicyReport fail ──

func extractKyvernoViolations(data map[string]any) []grc.Violation {
	var violations []grc.Violation
	// Check clusterpolicy enforcement mode
	cp := toMap(data["clusterpolicy"])
	if cp != nil {
		spec := toMap(cp["spec"])
		if spec != nil {
			action := str(spec, "validationFailureAction")
			if strings.ToLower(action) != "enforce" {
				cpMeta := toMap(cp["metadata"])
				cpName := ""
				if cpMeta != nil {
					cpName = str(cpMeta, "name")
				}
				violations = append(violations, grc.Violation{
					Field:       "validationFailureAction",
					Expected:    "enforce",
					Actual:      action,
					Description: fmt.Sprintf("ClusterPolicy '%s' validationFailureAction이 '%s' (enforce 필요)", cpName, action),
					Severity:    "high",
					K8sSource: grc.K8sSource{
						ResourceKind: "ClusterPolicy",
						ResourceName: cpName,
					},
				})
			}
		}
	}
	// Check policyreport fail count
	pr := toMap(data["policyreport_summary"])
	if pr != nil {
		if fail, ok := pr["fail"]; ok {
			if f, ok := fail.(float64); ok && f > 0 {
				violations = append(violations, grc.Violation{
					Field:       "policyreport_summary.fail",
					Expected:    "0",
					Actual:      fail,
					Description: fmt.Sprintf("PolicyReport에 %v건의 fail 리소스 존재", fail),
					Severity:    "high",
					K8sSource: grc.K8sSource{
						ResourceKind: "PolicyReport",
					},
				})
			}
		}
	}
	return violations
}

// ── 1.3.1-R007: git PR 없는 정책 변경 ──

func extractPolicyChangeViolations(data map[string]any) []grc.Violation {
	changes := toSlice(data["recent_policy_changes"])
	if len(changes) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, ch := range changes {
		m := toMap(ch)
		if m == nil {
			continue
		}
		prID := m["pr_id"]
		if prID == nil {
			policyName := str(m, "policy")
			auditLog := toMap(m["audit_log_event"])
			user := ""
			if auditLog != nil {
				user = str(auditLog, "user")
			}
			violations = append(violations, grc.Violation{
				Field:       "pr_id",
				Expected:    "non-null",
				Actual:      nil,
				Description: fmt.Sprintf("정책 '%s'이 git PR 없이 직접 적용됨 (user: %s)", policyName, user),
				Severity:    "high",
				K8sSource: grc.K8sSource{
					ResourceKind: "Policy",
					ResourceName: policyName,
				},
			})
		}
	}
	return violations
}

// ── 2.2.1-R002: 개별 RoleBinding으로 admin 부여 ──

func extractIndividualRBViolations(data map[string]any) []grc.Violation {
	rbs := toSlice(data["individual_rolebindings_with_admin"])
	if len(rbs) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, rb := range rbs {
		m := toMap(rb)
		if m == nil {
			continue
		}
		meta := toMap(m["metadata"])
		rbName := ""
		if meta != nil {
			rbName = str(meta, "name")
		}
		subjects := toSlice(m["subjects"])
		subjectName := ""
		if len(subjects) > 0 {
			if s := toMap(subjects[0]); s != nil {
				subjectName = str(s, "name")
			}
		}
		violations = append(violations, grc.Violation{
			Field:       "individual_rolebinding",
			Expected:    "group-based binding",
			Actual:      subjectName,
			Description: fmt.Sprintf("개별 사용자 '%s'에게 admin 권한 직접 부여 (RoleBinding: %s)", subjectName, rbName),
			Severity:    "high",
			K8sSource: grc.K8sSource{
				ResourceKind: "ClusterRoleBinding",
				ResourceName: rbName,
			},
		})
	}
	return violations
}

// ── 2.2.1-R007: audit log 미활성화/미비 ──

func extractAuditLogViolations(data map[string]any) []grc.Violation {
	var violations []grc.Violation
	if enabled, ok := boolVal(data, "audit_log_enabled"); ok && !enabled {
		clusterName := str(data, "cluster_name")
		violations = append(violations, grc.Violation{
			Field:       "audit_log_enabled",
			Expected:    "true",
			Actual:      false,
			Description: fmt.Sprintf("클러스터 '%s' audit log 비활성화", clusterName),
			Severity:    "critical",
			K8sSource: grc.K8sSource{
				ClusterName:  clusterName,
				ResourceKind: "Cluster",
				ResourceName: clusterName,
			},
		})
	}
	return violations
}

// ── 2.2.2-R002: 개발-운영 분리 위반 audit event ──

func extractAuditEventViolations(data map[string]any) []grc.Violation {
	events := toSlice(data["sample_violations"])
	if len(events) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, ev := range events {
		m := toMap(ev)
		if m == nil {
			continue
		}
		user := toMap(m["user"])
		userName := ""
		if user != nil {
			userName = str(user, "username")
		}
		objRef := toMap(m["objectRef"])
		ns, resource, name := "", "", ""
		if objRef != nil {
			ns = str(objRef, "namespace")
			resource = str(objRef, "resource")
			name = str(objRef, "name")
		}
		violations = append(violations, grc.Violation{
			Field:       "dev_prod_separation",
			Expected:    "개발/운영 환경 분리",
			Actual:      fmt.Sprintf("%s %s %s/%s", str(m, "verb"), resource, ns, name),
			Description: fmt.Sprintf("사용자 '%s'가 운영 환경에서 %s %s/%s 수행", userName, str(m, "verb"), ns, name),
			Severity:    "high",
			K8sSource: grc.K8sSource{
				Namespace:    ns,
				ResourceKind: resource,
				ResourceName: name,
			},
		})
	}
	return violations
}

// ── 2.2.2-R003: 시스템관리자-감사자 겸직 ──

func extractOverlapUserViolations(data map[string]any) []grc.Violation {
	users := toSlice(data["overlapping_users"])
	if len(users) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, u := range users {
		userName := fmt.Sprintf("%v", u)
		violations = append(violations, grc.Violation{
			Field:       "user_overlap",
			Expected:    "0",
			Actual:      userName,
			Description: fmt.Sprintf("사용자 '%s'가 시스템관리자·감사자 그룹 모두 소속", userName),
			Severity:    "high",
			K8sSource: grc.K8sSource{
				ResourceKind: "Group",
				ResourceName: userName,
			},
		})
	}
	return violations
}

// ── 2.2.2-R006: SoD 위반 ──

func extractSoDViolations(data map[string]any) []grc.Violation {
	viols := toSlice(data["sample_violations"])
	if len(viols) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, v := range viols {
		m := toMap(v)
		if m == nil {
			continue
		}
		subject := str(m, "subject")
		role1 := str(m, "role1")
		role2 := str(m, "role2")
		violations = append(violations, grc.Violation{
			Field:       "sod_violation",
			Expected:    "충돌 역할 미보유",
			Actual:      fmt.Sprintf("%s + %s", role1, role2),
			Description: fmt.Sprintf("SoD 위반: '%s'가 충돌 역할 보유 (%s + %s)", subject, role1, role2),
			Severity:    "high",
			K8sSource: grc.K8sSource{
				ResourceKind: "ClusterRoleBinding",
				ResourceName: subject,
			},
		})
	}
	return violations
}

// ── 2.2.2-R008: self-merge PR ──

func extractSelfMergePRViolations(data map[string]any) []grc.Violation {
	prs := toSlice(data["recent_prod_prs"])
	if len(prs) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, pr := range prs {
		m := toMap(pr)
		if m == nil {
			continue
		}
		selfMerge, _ := boolVal(m, "self_merge")
		if selfMerge {
			violations = append(violations, grc.Violation{
				Field:       "self_merge",
				Expected:    "false",
				Actual:      true,
				Description: fmt.Sprintf("PR %s이 self-merge됨 (이중 승인 미적용)", str(m, "pr")),
				Severity:    "high",
			})
		}
	}
	return violations
}

// ── 2.2.5-R003: 퇴직 후 RoleBinding 잔존 ──

func extractRemainingRBViolations(data map[string]any) []grc.Violation {
	rbs := toSlice(data["remaining_rolebindings_for_user"])
	if len(rbs) == 0 {
		return nil
	}
	user := str(data, "departing_user")
	if user == "" {
		user = str(data, "departed_user")
	}
	var violations []grc.Violation
	for _, rb := range rbs {
		rbName := fmt.Sprintf("%v", rb)
		violations = append(violations, grc.Violation{
			Field:       "remaining_rolebinding",
			Expected:    "삭제됨",
			Actual:      rbName,
			Description: fmt.Sprintf("퇴직자 '%s'의 RoleBinding '%s' 미삭제", user, rbName),
			Severity:    "critical",
			K8sSource: grc.K8sSource{
				ResourceKind: "RoleBinding",
				ResourceName: rbName,
			},
		})
	}
	return violations
}

// ── 2.2.5-R005: 직무 변경 후 기존 권한 잔존 ──

func extractOldPermViolations(data map[string]any) []grc.Violation {
	perms := toSlice(data["old_permissions_still_active"])
	if len(perms) == 0 {
		return nil
	}
	user := str(data, "user")
	var violations []grc.Violation
	for _, p := range perms {
		permName := fmt.Sprintf("%v", p)
		violations = append(violations, grc.Violation{
			Field:       "old_permission",
			Expected:    "revoked",
			Actual:      permName,
			Description: fmt.Sprintf("직무 변경된 '%s'의 이전 권한 '%s' 미회수", user, permName),
			Severity:    "high",
			K8sSource: grc.K8sSource{
				ResourceKind: "RoleBinding",
				ResourceName: permName,
			},
		})
	}
	return violations
}

// ── 2.2.5-R009: orphaned 계정 ──

func extractOrphanedAccountViolations(data map[string]any) []grc.Violation {
	var violations []grc.Violation
	for _, key := range []string{"orphaned_iam_users", "orphaned_service_accounts"} {
		items := toSlice(data[key])
		kind := "IAMUser"
		if strings.Contains(key, "service_account") {
			kind = "ServiceAccount"
		}
		for _, item := range items {
			name := fmt.Sprintf("%v", item)
			violations = append(violations, grc.Violation{
				Field:       key,
				Expected:    "삭제 또는 비활성화",
				Actual:      name,
				Description: fmt.Sprintf("미사용 %s '%s' 잔존", kind, name),
				Severity:    "high",
				K8sSource: grc.K8sSource{
					ResourceKind: kind,
					ResourceName: name,
				},
			})
		}
	}
	return violations
}

// ── 2.2.5-R010: 퇴직자 활동 감지 ──

func extractPostTermEventViolations(data map[string]any) []grc.Violation {
	events := toSlice(data["sample_events"])
	if len(events) == 0 {
		return nil
	}
	var violations []grc.Violation
	for _, ev := range events {
		m := toMap(ev)
		if m == nil {
			continue
		}
		user := toMap(m["user"])
		userName := ""
		if user != nil {
			userName = str(user, "username")
		}
		objRef := toMap(m["objectRef"])
		ns, resource, name := "", "", ""
		if objRef != nil {
			ns = str(objRef, "namespace")
			resource = str(objRef, "resource")
			name = str(objRef, "name")
		}
		violations = append(violations, grc.Violation{
			Field:       "post_termination_activity",
			Expected:    "활동 없음",
			Actual:      fmt.Sprintf("%s %s/%s", str(m, "verb"), resource, name),
			Description: fmt.Sprintf("퇴직자 '%s'의 퇴직 후 활동: %s %s/%s", userName, str(m, "verb"), ns, name),
			Severity:    "critical",
			K8sSource: grc.K8sSource{
				Namespace:    ns,
				ResourceKind: resource,
				ResourceName: name,
			},
		})
	}
	return violations
}
