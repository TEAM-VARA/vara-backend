package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RBACChainRepo는 RBAC 권한상승 분석 결과를 4개 테이블에 적재합니다.
//
// 저장 정책 (이력 미보존 / 클러스터별 덮어쓰기):
//   한 트랜잭션 안에서 해당 cluster 행을 모두 DELETE 후 새로 INSERT.
//   → 직전 분석엔 있었으나 사라진 SA 의 유령 행을 남기지 않음.
//   → 멱등: 같은 클러스터를 여러 번 분석해도 항상 최신 한 벌만 유지.
//
// 엔진 타입(fixpoint.Permission 등)에 의존하지 않도록 평범한 행 DTO 만 받습니다.
// 엔진 출력 → DTO 변환은 service 계층이 담당합니다.
type RBACChainRepo struct {
	pool *pgxpool.Pool
}

func NewRBACChainRepo(pool *pgxpool.Pool) *RBACChainRepo { return &RBACChainRepo{pool: pool} }

// ─────────────────────────────────────────
// 입력 DTO (service 가 채워서 넘김)
// ─────────────────────────────────────────

// RBACChainResult는 한 클러스터 분석 결과 전체입니다.
type RBACChainResult struct {
	Cluster         string
	SnapshotAt      time.Time  // RBAC 5종 공통 시점
	SnapshotAtPods  *time.Time // nil 가능
	SnapshotAtNodes *time.Time // nil 가능
	Summary         MetaSummary
	SAReports       []SAReportRow
	Escalations     []EscalationRow
	Permissions     []PermissionRow
}

// MetaSummary는 rbac_analysis_meta 한 행입니다.
type MetaSummary struct {
	TotalSAs        int
	ClusterAdminSAs int
	ChangedSAs      int
	MountedSAs      int
	RulesVersion    string // "" 면 NULL
}

// SAReportRow는 rbac_sa_reports 한 행입니다. (SA당 1행)
type SAReportRow struct {
	SANamespace         string
	SAName              string
	ReachesClusterAdmin bool
	InitialPermCount    int
	FinalPermCount      int
	DeltaCount          int
	AppliedTransitions  []byte // JSONB ["R-INDIRECT-04", ...]
	UsedByPods          []byte // JSONB [{name, namespace, ...}]
	DirectBindings      []byte // JSONB [{kind, name, ...}]
}

// EscalationRow는 rbac_escalation_paths 한 행입니다. (새로 흡수된 권한당 1행)
type EscalationRow struct {
	SANamespace    string
	SAName         string
	PermissionRepr string
	APIGroup       string
	Resource       string
	Verb           string
	Namespace      *string // 권한 한정 네임스페이스, nil = 클러스터 전체
	ViaTransition  string
	AbsorbedFromSA *string
}

// PermissionRow는 rbac_sa_permissions 한 행입니다. (최종 권한당 1행)
type PermissionRow struct {
	SANamespace    string
	SAName         string
	APIGroup       string
	Resource       string
	Verb           string
	Namespace      *string
	ResourceName   *string
	NonResourceURL *string
}

// ─────────────────────────────────────────
// 저장 (트랜잭션)
// ─────────────────────────────────────────

// Save는 한 클러스터의 분석 결과를 트랜잭션으로 덮어씁니다.
func (r *RBACChainRepo) Save(ctx context.Context, res RBACChainResult) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rbac_chain: begin tx: %w", err)
	}
	// Commit 전이면 Rollback (성공 후엔 no-op).
	defer func() { _ = tx.Rollback(ctx) }()

	// 1) 이 클러스터의 기존 행 전부 삭제 (유령 행 방지)
	for _, t := range []string{
		"rbac_sa_reports",
		"rbac_escalation_paths",
		"rbac_sa_permissions",
	} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+t+" WHERE cluster_name = $1", res.Cluster); err != nil {
			return fmt.Errorf("rbac_chain: delete %s: %w", t, err)
		}
	}

	// 2) meta upsert (클러스터당 1행)
	rulesVersion := any(nil)
	if res.Summary.RulesVersion != "" {
		rulesVersion = res.Summary.RulesVersion
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rbac_analysis_meta
		    (cluster_name, snapshot_at, snapshot_at_pods, snapshot_at_nodes,
		     total_sas, cluster_admin_sas, changed_sas, mounted_sas, rules_version, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (cluster_name) DO UPDATE SET
		    snapshot_at       = EXCLUDED.snapshot_at,
		    snapshot_at_pods  = EXCLUDED.snapshot_at_pods,
		    snapshot_at_nodes = EXCLUDED.snapshot_at_nodes,
		    total_sas         = EXCLUDED.total_sas,
		    cluster_admin_sas = EXCLUDED.cluster_admin_sas,
		    changed_sas       = EXCLUDED.changed_sas,
		    mounted_sas       = EXCLUDED.mounted_sas,
		    rules_version     = EXCLUDED.rules_version,
		    computed_at       = NOW()`,
		res.Cluster, res.SnapshotAt, res.SnapshotAtPods, res.SnapshotAtNodes,
		res.Summary.TotalSAs, res.Summary.ClusterAdminSAs, res.Summary.ChangedSAs,
		res.Summary.MountedSAs, rulesVersion,
	); err != nil {
		return fmt.Errorf("rbac_chain: upsert meta: %w", err)
	}

	// 3) 본문 배치 INSERT
	batch := &pgx.Batch{}

	for _, s := range res.SAReports {
		batch.Queue(`
			INSERT INTO rbac_sa_reports
			    (cluster_name, sa_namespace, sa_name, snapshot_at, reaches_cluster_admin,
			     initial_perm_count, final_perm_count, delta_count,
			     applied_transitions, used_by_pods, direct_bindings)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			res.Cluster, s.SANamespace, s.SAName, res.SnapshotAt, s.ReachesClusterAdmin,
			s.InitialPermCount, s.FinalPermCount, s.DeltaCount,
			jsonbOrEmpty(s.AppliedTransitions, "[]"),
			jsonbOrEmpty(s.UsedByPods, "[]"),
			jsonbOrEmpty(s.DirectBindings, "[]"),
		)
	}

	for _, e := range res.Escalations {
		batch.Queue(`
			INSERT INTO rbac_escalation_paths
			    (cluster_name, sa_namespace, sa_name, permission_repr,
			     api_group, resource, verb, namespace, via_transition, absorbed_from_sa)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			res.Cluster, e.SANamespace, e.SAName, e.PermissionRepr,
			e.APIGroup, e.Resource, e.Verb, e.Namespace, e.ViaTransition, e.AbsorbedFromSA,
		)
	}

	for _, p := range res.Permissions {
		batch.Queue(`
			INSERT INTO rbac_sa_permissions
			    (cluster_name, sa_namespace, sa_name,
			     api_group, resource, verb, namespace, resource_name, non_resource_url)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			res.Cluster, p.SANamespace, p.SAName,
			p.APIGroup, p.Resource, p.Verb, p.Namespace, p.ResourceName, p.NonResourceURL,
		)
	}

	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return fmt.Errorf("rbac_chain: batch insert[%d]: %w", i, err)
			}
		}
		if err := br.Close(); err != nil {
			return fmt.Errorf("rbac_chain: batch close: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rbac_chain: commit: %w", err)
	}
	return nil
}

// jsonbOrEmpty — nil/빈 바이트면 기본값(예: "[]") 으로 대체.
func jsonbOrEmpty(b []byte, def string) []byte {
	if len(b) == 0 {
		return []byte(def)
	}
	return b
}
