package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ─────────────────────────────────────────
// 조회 결과 DTO (handler 가 JSON 으로 그대로 응답)
// ─────────────────────────────────────────

// MetaOut은 rbac_analysis_meta 한 행입니다.
type MetaOut struct {
	Cluster         string     `json:"cluster_name"`
	SnapshotAt      time.Time  `json:"snapshot_at"`
	SnapshotAtPods  *time.Time `json:"snapshot_at_pods"`
	SnapshotAtNodes *time.Time `json:"snapshot_at_nodes"`
	ComputedAt      time.Time  `json:"computed_at"`
	TotalSAs        int        `json:"total_sas"`
	ClusterAdminSAs int        `json:"cluster_admin_sas"`
	ChangedSAs      int        `json:"changed_sas"`
	MountedSAs      int        `json:"mounted_sas"`
	RulesVersion    *string    `json:"rules_version"`
}

// SAReportOut은 rbac_sa_reports 한 행입니다.
type SAReportOut struct {
	SANamespace         string          `json:"sa_namespace"`
	SAName              string          `json:"sa_name"`
	ReachesClusterAdmin bool            `json:"reaches_cluster_admin"`
	InitialPermCount    int             `json:"initial_perm_count"`
	FinalPermCount      int             `json:"final_perm_count"`
	DeltaCount          int             `json:"delta_count"`
	AppliedTransitions  json.RawMessage `json:"applied_transitions"`
	TransitionTriggers  json.RawMessage `json:"transition_triggers"`
	UsedByPods          json.RawMessage `json:"used_by_pods"`
	DirectBindings      json.RawMessage `json:"direct_bindings"`
}

// EscalationOut은 rbac_escalation_paths 한 행입니다.
type EscalationOut struct {
	PermissionRepr string  `json:"permission_repr"`
	APIGroup       string  `json:"api_group"`
	Resource       string  `json:"resource"`
	Verb           string  `json:"verb"`
	Namespace      *string `json:"namespace"`
	ViaTransition  string  `json:"via_transition"`
	AbsorbedFromSA *string `json:"absorbed_from_sa"`
}

// SADetailOut은 SA 한 개의 상세(성적표 + 권한상승 경로)입니다.
type SADetailOut struct {
	Report     SAReportOut     `json:"report"`
	Escalation []EscalationOut `json:"escalation_paths"`
}

// PermissionOut은 rbac_sa_permissions 한 행입니다. (SA 최종 권한 1개)
type PermissionOut struct {
	APIGroup       string  `json:"api_group"`        // "" = core, "*" = 전체
	Resource       string  `json:"resource"`         // secrets, pods, "*" ...
	Verb           string  `json:"verb"`             // get, list, "*" ...
	Namespace      *string `json:"namespace"`        // null = 클러스터 전체
	ResourceName   *string `json:"resource_name"`    // 특정 자원 한정 (보통 null)
	NonResourceURL *string `json:"non_resource_url"` // URL 권한 (/metrics 등, 보통 null)
}

// SAPermMatchOut은 권한 역질의 결과 한 행입니다. (그 권한을 가진 SA + 매칭된 범위)
type SAPermMatchOut struct {
	SANamespace  string  `json:"sa_namespace"`
	SAName       string  `json:"sa_name"`
	APIGroup     string  `json:"api_group"`
	Resource     string  `json:"resource"`      // 매칭된 실제 값 ("*" 면 와일드카드로 매칭됨)
	Verb         string  `json:"verb"`          // 매칭된 실제 값 ("*" 가능)
	Namespace    *string `json:"namespace"`     // null = 클러스터 전체
	ResourceName *string `json:"resource_name"` // 보통 null
}

// RuleCatalogOut은 rbac_rule_catalog 한 행입니다. (룰셋 전역 참조 데이터, 050)
// applied_transitions / via_transition 의 룰 ID 를 제목·설명으로 풀기 위해 FE 가 사용.
type RuleCatalogOut struct {
	RuleID          string          `json:"rule_id"`
	Category        string          `json:"category"`         // direct | indirect | lateral
	SchemaVersion   string          `json:"schema_version"`   // "0.1" | "1.0"
	Title           string          `json:"title"`            // 룰 YAML 원본 description
	SummaryKo       string          `json:"summary_ko"`       // 사람용 한글 설명
	MatchKind       string          `json:"match_kind"`       // any_of | all_of
	MatchPerms      json.RawMessage `json:"match_perms"`      // 매칭 권한 조합 (JSONB)
	EngineStatus    string          `json:"engine_status"`    // default | opt-in | unwired
	TransitionGroup *string         `json:"transition_group"` // A|B|C|D|F|G (nullable)
	OptInFlag       *string         `json:"opt_in_flag"`      // "include-eks-specific" 등 (nullable)
	Sources         json.RawMessage `json:"sources"`          // [{type, name, url}] (JSONB)
}

// ─────────────────────────────────────────
// 조회
// ─────────────────────────────────────────

// GetMeta — 클러스터 분석 현황 1행. 없으면 (nil, nil).
func (r *RBACChainRepo) GetMeta(ctx context.Context, cluster string) (*MetaOut, error) {
	var m MetaOut
	err := r.pool.QueryRow(ctx, `
		SELECT cluster_name, snapshot_at, snapshot_at_pods, snapshot_at_nodes,
		       computed_at, total_sas, cluster_admin_sas, changed_sas, mounted_sas, rules_version
		FROM rbac_analysis_meta WHERE cluster_name = $1`, cluster,
	).Scan(&m.Cluster, &m.SnapshotAt, &m.SnapshotAtPods, &m.SnapshotAtNodes,
		&m.ComputedAt, &m.TotalSAs, &m.ClusterAdminSAs, &m.ChangedSAs, &m.MountedSAs, &m.RulesVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("rbac_chain: get meta: %w", err)
	}
	return &m, nil
}

// ListSAReports — 클러스터의 모든 SA 성적표 (위험 우선 → delta 큰 순).
func (r *RBACChainRepo) ListSAReports(ctx context.Context, cluster string) ([]SAReportOut, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT sa_namespace, sa_name, reaches_cluster_admin,
		       initial_perm_count, final_perm_count, delta_count,
		       applied_transitions, transition_triggers, used_by_pods, direct_bindings
		FROM rbac_sa_reports
		WHERE cluster_name = $1
		ORDER BY reaches_cluster_admin DESC, delta_count DESC, sa_namespace, sa_name`, cluster)
	if err != nil {
		return nil, fmt.Errorf("rbac_chain: list sa reports: %w", err)
	}
	defer rows.Close()

	out := []SAReportOut{}
	for rows.Next() {
		var s SAReportOut
		if err := rows.Scan(&s.SANamespace, &s.SAName, &s.ReachesClusterAdmin,
			&s.InitialPermCount, &s.FinalPermCount, &s.DeltaCount,
			&s.AppliedTransitions, &s.TransitionTriggers, &s.UsedByPods, &s.DirectBindings); err != nil {
			return nil, fmt.Errorf("rbac_chain: scan sa report: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetSADetail — SA 한 개의 성적표 + 권한상승 경로. 성적표 없으면 (nil, nil).
func (r *RBACChainRepo) GetSADetail(ctx context.Context, cluster, ns, name string) (*SADetailOut, error) {
	var s SAReportOut
	err := r.pool.QueryRow(ctx, `
		SELECT sa_namespace, sa_name, reaches_cluster_admin,
		       initial_perm_count, final_perm_count, delta_count,
		       applied_transitions, transition_triggers, used_by_pods, direct_bindings
		FROM rbac_sa_reports
		WHERE cluster_name = $1 AND sa_namespace = $2 AND sa_name = $3`, cluster, ns, name,
	).Scan(&s.SANamespace, &s.SAName, &s.ReachesClusterAdmin,
		&s.InitialPermCount, &s.FinalPermCount, &s.DeltaCount,
		&s.AppliedTransitions, &s.TransitionTriggers, &s.UsedByPods, &s.DirectBindings)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("rbac_chain: get sa detail: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT permission_repr, api_group, resource, verb, namespace, via_transition, absorbed_from_sa
		FROM rbac_escalation_paths
		WHERE cluster_name = $1 AND sa_namespace = $2 AND sa_name = $3
		ORDER BY via_transition, permission_repr`, cluster, ns, name)
	if err != nil {
		return nil, fmt.Errorf("rbac_chain: list escalation: %w", err)
	}
	defer rows.Close()

	esc := []EscalationOut{}
	for rows.Next() {
		var e EscalationOut
		if err := rows.Scan(&e.PermissionRepr, &e.APIGroup, &e.Resource, &e.Verb,
			&e.Namespace, &e.ViaTransition, &e.AbsorbedFromSA); err != nil {
			return nil, fmt.Errorf("rbac_chain: scan escalation: %w", err)
		}
		esc = append(esc, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &SADetailOut{Report: s, Escalation: esc}, nil
}

// ListSAPermissions — SA 한 개의 최종 권한 전체 (rbac_sa_permissions). RC-5b.
// 결과 없으면 빈 슬라이스. (SA 존재 여부는 별도 판단 — 보통 RC-2 와 함께 호출)
func (r *RBACChainRepo) ListSAPermissions(ctx context.Context, cluster, ns, name string) ([]PermissionOut, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT api_group, resource, verb, namespace, resource_name, non_resource_url
		FROM rbac_sa_permissions
		WHERE cluster_name = $1 AND sa_namespace = $2 AND sa_name = $3
		ORDER BY api_group, resource, verb, namespace`, cluster, ns, name)
	if err != nil {
		return nil, fmt.Errorf("rbac_chain: list sa permissions: %w", err)
	}
	defer rows.Close()

	out := []PermissionOut{}
	for rows.Next() {
		var p PermissionOut
		if err := rows.Scan(&p.APIGroup, &p.Resource, &p.Verb,
			&p.Namespace, &p.ResourceName, &p.NonResourceURL); err != nil {
			return nil, fmt.Errorf("rbac_chain: scan sa permission: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FindSAsByPermission — 특정 resource/verb 권한을 가진 SA 목록 (역질의). RC-5a.
// 와일드카드 포함: resource/verb 가 정확히 일치하거나 '*' 인 행도 매칭한다
// (예: cluster-admin 의 */*.* 도 secrets.get 질의에 잡힘). idx_perms_lookup 사용.
func (r *RBACChainRepo) FindSAsByPermission(ctx context.Context, cluster, resource, verb string) ([]SAPermMatchOut, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT sa_namespace, sa_name, api_group, resource, verb, namespace, resource_name
		FROM rbac_sa_permissions
		WHERE cluster_name = $1
		  AND (resource = $2 OR resource = '*')
		  AND (verb = $3 OR verb = '*')
		ORDER BY sa_namespace, sa_name, api_group, resource, verb`, cluster, resource, verb)
	if err != nil {
		return nil, fmt.Errorf("rbac_chain: find sas by permission: %w", err)
	}
	defer rows.Close()

	out := []SAPermMatchOut{}
	for rows.Next() {
		var m SAPermMatchOut
		if err := rows.Scan(&m.SANamespace, &m.SAName, &m.APIGroup, &m.Resource, &m.Verb,
			&m.Namespace, &m.ResourceName); err != nil {
			return nil, fmt.Errorf("rbac_chain: scan sa perm match: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListRuleCatalog — RBAC 권한상승 룰 카탈로그(rbac_rule_catalog, 22종) 조회. RC-4.
//
//	category     "" | direct | indirect | lateral
//	engineStatus "" | default | opt-in | unwired
//
// 빈 문자열은 해당 필터 미적용. rule_id 오름차순.
func (r *RBACChainRepo) ListRuleCatalog(ctx context.Context, category, engineStatus string) ([]RuleCatalogOut, error) {
	q := `
		SELECT rule_id, category, schema_version, title, summary_ko,
		       match_kind, match_perms, engine_status, transition_group, opt_in_flag, sources
		FROM rbac_rule_catalog`

	conds := []string{}
	args := []any{}
	if category != "" {
		args = append(args, category)
		conds = append(conds, fmt.Sprintf("category = $%d", len(args)))
	}
	if engineStatus != "" {
		args = append(args, engineStatus)
		conds = append(conds, fmt.Sprintf("engine_status = $%d", len(args)))
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY rule_id"

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("rbac_chain: list rule catalog: %w", err)
	}
	defer rows.Close()

	out := []RuleCatalogOut{}
	for rows.Next() {
		var c RuleCatalogOut
		if err := rows.Scan(&c.RuleID, &c.Category, &c.SchemaVersion, &c.Title, &c.SummaryKo,
			&c.MatchKind, &c.MatchPerms, &c.EngineStatus, &c.TransitionGroup, &c.OptInFlag, &c.Sources); err != nil {
			return nil, fmt.Errorf("rbac_chain: scan rule catalog: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
