package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vara/backend/internal/rbacchain/directperm"
	"github.com/vara/backend/internal/rbacchain/fixpoint"
	"github.com/vara/backend/internal/rbacchain/loader"
	"github.com/vara/backend/internal/rbacchain/sareport"
	"github.com/vara/backend/internal/rbacchain/snapshot"
	"github.com/vara/backend/internal/repository/postgres"
)

// RBACChainService는 RBAC 권한상승(fixpoint) 분석을 수행하고 결과를 DB에 저장합니다.
//
// 파이프라인 (파일 산출물 없음):
//
//	loader.Load(DB→메모리 snapshot)
//	  → directperm.Extract
//	  → fixpoint.RunFixpoint
//	  → sareport.Build  +  fixpoint.NewlyAbsorbedRecords
//	  → repo.Save (4개 표 트랜잭션 적재)
type RBACChainService struct {
	loader     loader.SnapshotLoader
	repo       *postgres.RBACChainRepo
	includeEKS bool // R-INDIRECT-16 (EKS aws-auth) 옵트인
}

// NewRBACChainService — includeEKS 는 EKS 전용 룰(R-INDIRECT-16) 활성 여부.
func NewRBACChainService(l loader.SnapshotLoader, repo *postgres.RBACChainRepo, includeEKS bool) *RBACChainService {
	return &RBACChainService{loader: l, repo: repo, includeEKS: includeEKS}
}

// Compute — 한 클러스터를 분석하고 결과를 DB에 덮어쓴다. 요약을 반환.
func (s *RBACChainService) Compute(ctx context.Context, cluster string) (postgres.MetaSummary, error) {
	snap, err := s.loader.Load(ctx, cluster)
	if err != nil {
		return postgres.MetaSummary{}, err
	}

	dp, err := directperm.Extract(snap)
	if err != nil {
		return postgres.MetaSummary{}, fmt.Errorf("directperm extract: %w", err)
	}

	initialPerms := fixpoint.InitialPermsFromDP(dp)
	initialProv := fixpoint.InitialProvenanceFromDP(dp)
	initialSnapshot := fixpoint.SnapshotInitialPerms(initialPerms) // delta 계산용 사본

	activeFlags := map[string]struct{}{}
	if s.includeEKS {
		activeFlags["include-eks-specific"] = struct{}{}
	}

	allPerms, provenance, err := fixpoint.RunFixpoint(initialPerms, snap, nil, activeFlags, initialProv)
	if err != nil {
		return postgres.MetaSummary{}, fmt.Errorf("fixpoint: %w", err)
	}

	// sareport 입력(메모리) → 종합 보고서
	allPermsObj, deltaObj, err := fixpoint.BuildReportInputs(allPerms, initialSnapshot, provenance)
	if err != nil {
		return postgres.MetaSummary{}, fmt.Errorf("build report inputs: %w", err)
	}
	report := sareport.Build("", snap, allPermsObj, deltaObj)

	// ── snapshot_at 들 (snap 의 captured_at* 문자열 파싱) ──
	rbacAt, err := parseISOTime(snap["captured_at"])
	if err != nil {
		return postgres.MetaSummary{}, fmt.Errorf("captured_at 파싱: %w", err)
	}

	res := postgres.RBACChainResult{
		Cluster:         cluster,
		SnapshotAt:      rbacAt,
		SnapshotAtPods:  parseISOTimePtr(snap["captured_at_pods"]),
		SnapshotAtNodes: parseISOTimePtr(snap["captured_at_nodes"]),
		Summary: postgres.MetaSummary{
			TotalSAs:        report.Summary.TotalSAs,
			ClusterAdminSAs: report.Summary.ClusterAdminSAs,
			ChangedSAs:      report.Summary.ChangedSAs,
			MountedSAs:      report.Summary.MountedSAs,
		},
	}

	// ── SA별 성적표 → rbac_sa_reports ──
	res.SAReports = make([]postgres.SAReportRow, 0, len(report.SAs))
	for _, sa := range report.SAs {
		at, _ := json.Marshal(sa.AppliedTransitions)
		pods, _ := json.Marshal(sa.UsedByPods)
		binds, _ := json.Marshal(sa.DirectBindings)
		res.SAReports = append(res.SAReports, postgres.SAReportRow{
			SANamespace:         sa.Namespace,
			SAName:              sa.Name,
			ReachesClusterAdmin: sa.ReachesClusterAdmin,
			InitialPermCount:    sa.InitialPermCount,
			FinalPermCount:      sa.FinalPermCount,
			DeltaCount:          sa.FinalPermCount - sa.InitialPermCount,
			AppliedTransitions:  at,
			UsedByPods:          pods,
			DirectBindings:      binds,
		})
	}

	// ── 권한상승 경로 → rbac_escalation_paths ──
	for _, rec := range fixpoint.NewlyAbsorbedRecords(allPerms, initialSnapshot, provenance) {
		res.Escalations = append(res.Escalations, postgres.EscalationRow{
			SANamespace:    rec.SA.Namespace,
			SAName:         rec.SA.Name,
			PermissionRepr: rec.PermRepr,
			APIGroup:       rec.Perm.APIGroup,
			Resource:       rec.Perm.Resource,
			Verb:           rec.Perm.Verb,
			Namespace:      nullStrPtr(rec.Perm.Namespace),
			ViaTransition:  rec.ViaTransition,
			AbsorbedFromSA: emptyToNil(rec.AbsorbedFromSA),
		})
	}

	// ── 최종 권한 전체 → rbac_sa_permissions ──
	for sa, ps := range allPerms {
		for _, p := range ps.Iter() {
			res.Permissions = append(res.Permissions, postgres.PermissionRow{
				SANamespace:    sa.Namespace,
				SAName:         sa.Name,
				APIGroup:       p.APIGroup,
				Resource:       p.Resource,
				Verb:           p.Verb,
				Namespace:      nullStrPtr(p.Namespace),
				ResourceName:   nullStrPtr(p.ResourceName),
				NonResourceURL: nullStrPtr(p.NonResourceURL),
			})
		}
	}

	if err := s.repo.Save(ctx, res); err != nil {
		return postgres.MetaSummary{}, err
	}
	return res.Summary, nil
}

// ── 조회 (repo 패스스루) ──

// GetCluster — 클러스터 분석 현황(meta) + SA 성적표 목록. meta 없으면 (nil, nil, nil).
func (s *RBACChainService) GetCluster(ctx context.Context, cluster string) (*postgres.MetaOut, []postgres.SAReportOut, error) {
	meta, err := s.repo.GetMeta(ctx, cluster)
	if err != nil {
		return nil, nil, err
	}
	if meta == nil {
		return nil, nil, nil
	}
	reports, err := s.repo.ListSAReports(ctx, cluster)
	if err != nil {
		return nil, nil, err
	}
	return meta, reports, nil
}

// GetSA — SA 한 개의 상세(성적표 + 권한상승 경로). 없으면 (nil, nil).
func (s *RBACChainService) GetSA(ctx context.Context, cluster, ns, name string) (*postgres.SADetailOut, error) {
	return s.repo.GetSADetail(ctx, cluster, ns, name)
}

// ── helpers ──

// parseISOTime — captured_at(ISO8601 문자열) → time.Time.
func parseISOTime(v any) (time.Time, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}, fmt.Errorf("시점 값이 문자열이 아님: %T", v)
	}
	return time.Parse(time.RFC3339, s)
}

// parseISOTimePtr — nil/빈/파싱실패면 nil 반환 (pods/nodes 시점은 nullable).
func parseISOTimePtr(v any) *time.Time {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// nullStrPtr — NullString → *string (Null 이면 nil).
func nullStrPtr(n snapshot.NullString) *string {
	if n.IsNull {
		return nil
	}
	v := n.Value
	return &v
}

// emptyToNil — "" → nil, 아니면 *string.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
