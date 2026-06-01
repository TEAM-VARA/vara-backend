package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		       applied_transitions, used_by_pods, direct_bindings
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
			&s.AppliedTransitions, &s.UsedByPods, &s.DirectBindings); err != nil {
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
		       applied_transitions, used_by_pods, direct_bindings
		FROM rbac_sa_reports
		WHERE cluster_name = $1 AND sa_namespace = $2 AND sa_name = $3`, cluster, ns, name,
	).Scan(&s.SANamespace, &s.SAName, &s.ReachesClusterAdmin,
		&s.InitialPermCount, &s.FinalPermCount, &s.DeltaCount,
		&s.AppliedTransitions, &s.UsedByPods, &s.DirectBindings)
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
