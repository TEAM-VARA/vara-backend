package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IamPrivescResultRepo 는 IAM 권한상승 탐지 "결과"(scan_runs / principal_results / findings)를
// 프론트엔드가 읽을 수 있게 조회한다. 쓰기는 IamPrivescRepo, 읽기는 이 repo 가 담당한다.
// "현재 posture"는 계정별 최신 실행 뷰(latest_scan_runs)를 기준으로 한다.
type IamPrivescResultRepo struct {
	pool *pgxpool.Pool
}

func NewIamPrivescResultRepo(pool *pgxpool.Pool) *IamPrivescResultRepo {
	return &IamPrivescResultRepo{pool: pool}
}

// ScanRunRow = scan_runs 한 행(계정별 한 번의 룰셋 평가 요약).
type ScanRunRow struct {
	RunID           int64      `json:"run_id"`
	AccountID       string     `json:"account_id"`
	AccountAlias    *string    `json:"account_alias"`
	SourceScannedAt *time.Time `json:"source_scanned_at"`
	RulesetName     *string    `json:"ruleset_name"`
	RulesetVersion  *string    `json:"ruleset_version"`
	CoreOnly        bool       `json:"core_only"`
	TotalPrincipals int        `json:"total_principals"`
	CriticalCount   int        `json:"critical_count"`
	WarningCount    int        `json:"warning_count"`
	InfoCount       int        `json:"info_count"`
	OkCount         int        `json:"ok_count"`
	DetectedAt      time.Time  `json:"detected_at"`
}

// PrincipalResultRow = principal_results 한 행(principal 1개의 최종 상태).
type PrincipalResultRow struct {
	ID            int64    `json:"id"`
	RunID         int64    `json:"run_id"`
	AccountID     string   `json:"account_id"`
	PrincipalKind string   `json:"principal_kind"`
	PrincipalName string   `json:"principal_name"`
	PrincipalArn  string   `json:"principal_arn"`
	Status        string   `json:"status"`
	Notes         []string `json:"notes"`
}

// FindingRow = findings 한 행(단일 룰 또는 콤보 발견).
type FindingRow struct {
	ID            int64    `json:"id"`
	RunID         int64    `json:"run_id"`
	AccountID     string   `json:"account_id"`
	PrincipalKind string   `json:"principal_kind"`
	PrincipalName string   `json:"principal_name"`
	PrincipalArn  string   `json:"principal_arn"`
	FindingType   string   `json:"finding_type"`
	RuleID        string   `json:"rule_id"`
	Action        string   `json:"action"`
	Severity      string   `json:"severity"`
	BaseSeverity  string   `json:"base_severity"`
	IsCore        bool     `json:"is_core"`
	TitleKo       string   `json:"title_ko"`
	Category      string   `json:"category"`
	Notes         []string `json:"notes"`
	Sources       []string `json:"sources"`
	AwsDoc        string   `json:"aws_doc"`
}

// jsonbToStrings 는 JSONB 배열 컬럼(notes/sources)을 []string 으로 디코드한다(항상 비-nil).
func jsonbToStrings(b []byte) []string {
	if len(b) == 0 {
		return []string{}
	}
	var s []string
	if err := json.Unmarshal(b, &s); err != nil || s == nil {
		return []string{}
	}
	return s
}

// ListLatestScanRuns 는 계정별 "최신" 실행 요약을 반환한다(latest_scan_runs 뷰). accountID 비면 전체.
func (r *IamPrivescResultRepo) ListLatestScanRuns(ctx context.Context, accountID string) ([]ScanRunRow, error) {
	q := `SELECT run_id, account_id, account_alias, source_scanned_at, ruleset_name, ruleset_version,
	             core_only, total_principals, critical_count, warning_count, info_count, ok_count, detected_at
	      FROM latest_scan_runs`
	var args []any
	if accountID != "" {
		q += ` WHERE account_id = $1`
		args = append(args, accountID)
	}
	q += ` ORDER BY account_id`

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query latest_scan_runs: %w", err)
	}
	defer rows.Close()

	out := []ScanRunRow{}
	for rows.Next() {
		var s ScanRunRow
		if err := rows.Scan(&s.RunID, &s.AccountID, &s.AccountAlias, &s.SourceScannedAt,
			&s.RulesetName, &s.RulesetVersion, &s.CoreOnly, &s.TotalPrincipals,
			&s.CriticalCount, &s.WarningCount, &s.InfoCount, &s.OkCount, &s.DetectedAt); err != nil {
			return nil, fmt.Errorf("scan scan_run: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListCurrentPrincipals 는 계정별 최신 실행의 principal 결과를 반환한다.
// accountID/status 는 비면 필터 안 함. 정렬: 위험도(critical→ok)→kind→name.
func (r *IamPrivescResultRepo) ListCurrentPrincipals(ctx context.Context, accountID, status string) ([]PrincipalResultRow, error) {
	q := `SELECT pr.id, pr.run_id, pr.account_id, pr.principal_kind, pr.principal_name, pr.principal_arn, pr.status, pr.notes
	      FROM principal_results pr
	      JOIN latest_scan_runs lr ON lr.run_id = pr.run_id`
	var conds []string
	var args []any
	if accountID != "" {
		args = append(args, accountID)
		conds = append(conds, fmt.Sprintf("pr.account_id = $%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		conds = append(conds, fmt.Sprintf("pr.status = $%d", len(args)))
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY pr.account_id,
	       CASE pr.status WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'info' THEN 2 ELSE 3 END,
	       pr.principal_kind, pr.principal_name`

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query principal_results: %w", err)
	}
	defer rows.Close()

	out := []PrincipalResultRow{}
	for rows.Next() {
		var p PrincipalResultRow
		var notes []byte
		if err := rows.Scan(&p.ID, &p.RunID, &p.AccountID, &p.PrincipalKind, &p.PrincipalName,
			&p.PrincipalArn, &p.Status, &notes); err != nil {
			return nil, fmt.Errorf("scan principal_result: %w", err)
		}
		p.Notes = jsonbToStrings(notes)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListCurrentFindings 는 계정별 최신 실행의 발견 항목을 반환한다.
// accountID/severity/principalName 은 비면 필터 안 함. 정렬: 계정→principal→위험도→id.
func (r *IamPrivescResultRepo) ListCurrentFindings(ctx context.Context, accountID, severity, principalName string) ([]FindingRow, error) {
	q := `SELECT f.id, f.run_id, f.account_id, f.principal_kind, f.principal_name, f.principal_arn,
	             f.finding_type, f.rule_id, f.action, f.severity, f.base_severity, f.is_core,
	             f.title_ko, f.category, f.notes, f.sources, f.aws_doc
	      FROM findings f
	      JOIN latest_scan_runs lr ON lr.run_id = f.run_id`
	var conds []string
	var args []any
	if accountID != "" {
		args = append(args, accountID)
		conds = append(conds, fmt.Sprintf("f.account_id = $%d", len(args)))
	}
	if severity != "" {
		args = append(args, severity)
		conds = append(conds, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if principalName != "" {
		args = append(args, principalName)
		conds = append(conds, fmt.Sprintf("f.principal_name = $%d", len(args)))
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY f.account_id, f.principal_kind, f.principal_name,
	       CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'info' THEN 2 ELSE 3 END,
	       f.id`

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	out := []FindingRow{}
	for rows.Next() {
		var f FindingRow
		var notes, sources []byte
		if err := rows.Scan(&f.ID, &f.RunID, &f.AccountID, &f.PrincipalKind, &f.PrincipalName, &f.PrincipalArn,
			&f.FindingType, &f.RuleID, &f.Action, &f.Severity, &f.BaseSeverity, &f.IsCore,
			&f.TitleKo, &f.Category, &notes, &sources, &f.AwsDoc); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		f.Notes = jsonbToStrings(notes)
		f.Sources = jsonbToStrings(sources)
		out = append(out, f)
	}
	return out, rows.Err()
}
