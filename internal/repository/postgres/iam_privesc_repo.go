package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/iamprivesc/engine"
)

// IamPrivescRepo 는 소스 테이블(iam_authorization_snapshots) 읽기와
// 결과 테이블(scan_runs/principal_results/findings) 쓰기를 담당한다.
// aws_reader_repo.go 의 repo 패턴(구조체+pool, tx, json.Marshal→jsonb)을 따른다.
type IamPrivescRepo struct {
	pool *pgxpool.Pool
}

func NewIamPrivescRepo(pool *pgxpool.Pool) *IamPrivescRepo {
	return &IamPrivescRepo{pool: pool}
}

// ReadSnapshots 는 소스 테이블에서 계정 스냅샷을 읽어 엔진 입력으로 변환한다.
// accountID 가 비면 전체 계정(각 최신 1행). (Python read_snapshots_from_db 대응)
func (r *IamPrivescRepo) ReadSnapshots(ctx context.Context, accountID string) ([]engine.Snapshot, error) {
	q := `
		SELECT account_id, account_alias, snapshot_at,
		       user_detail_list, role_detail_list, group_detail_list, policies
		FROM iam_authorization_snapshots`
	var args []any
	if accountID != "" {
		q += " WHERE account_id = $1"
		args = append(args, accountID)
	}
	q += " ORDER BY account_id"

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer rows.Close()

	var out []engine.Snapshot
	for rows.Next() {
		var (
			s                  engine.Snapshot
			alias              *string
			ub, rb, gb, pb     []byte
		)
		if err := rows.Scan(&s.AccountID, &alias, &s.ScannedAt, &ub, &rb, &gb, &pb); err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		if alias != nil {
			s.AccountAlias = *alias
		}
		if err := json.Unmarshal(ub, &s.Users); err != nil {
			return nil, fmt.Errorf("unmarshal user_detail_list (%s): %w", s.AccountID, err)
		}
		if err := json.Unmarshal(rb, &s.Roles); err != nil {
			return nil, fmt.Errorf("unmarshal role_detail_list (%s): %w", s.AccountID, err)
		}
		if err := json.Unmarshal(gb, &s.Groups); err != nil {
			return nil, fmt.Errorf("unmarshal group_detail_list (%s): %w", s.AccountID, err)
		}
		if err := json.Unmarshal(pb, &s.Policies); err != nil {
			return nil, fmt.Errorf("unmarshal policies (%s): %w", s.AccountID, err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WriteResults 는 한 스냅샷의 탐지 결과를 result 테이블에 적재하고 run_id 를 반환한다.
// scan_runs INSERT ... RETURNING → principal_results/findings 일괄(Batch) 적재.
// (Python write_results 대응) append 모델이라 ON CONFLICT 불필요.
func (r *IamPrivescRepo) WriteResults(
	ctx context.Context,
	snap engine.Snapshot,
	results []engine.PrincipalResult,
	sum engine.Summary,
	rs engine.Ruleset,
	coreOnly bool,
) (int64, error) {

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	var runID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO scan_runs
			(account_id, account_alias, source_scanned_at, ruleset_name, ruleset_version,
			 core_only, total_principals, critical_count, warning_count, info_count, ok_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING run_id`,
		snap.AccountID, nullStr(snap.AccountAlias), nullTime(snap.ScannedAt),
		nullStr(rs.Name), nullStr(rs.Version), coreOnly,
		sum.Total, sum.Critical, sum.Warning, sum.Info, sum.Ok,
	).Scan(&runID)
	if err != nil {
		return 0, fmt.Errorf("insert scan_run: %w", err)
	}

	batch := &pgx.Batch{}
	for _, pr := range results {
		notes, _ := json.Marshal(pr.Notes)
		batch.Queue(`
			INSERT INTO principal_results
				(run_id, account_id, principal_kind, principal_name, principal_arn, status, notes)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			runID, snap.AccountID, pr.Kind, pr.Name, pr.Arn, pr.Status, notes)
	}
	for _, pr := range results {
		for _, f := range pr.Findings {
			notes, _ := json.Marshal(f.Notes)
			sources, _ := json.Marshal(f.Sources)
			batch.Queue(`
				INSERT INTO findings
					(run_id, account_id, principal_kind, principal_name, principal_arn,
					 finding_type, rule_id, action, severity, base_severity, is_core,
					 title_ko, category, notes, sources, aws_doc)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				runID, snap.AccountID, pr.Kind, pr.Name, pr.Arn,
				f.Type, f.ID, f.Action, f.Severity, f.BaseSeverity, f.Core,
				f.TitleKo, f.Category, notes, sources, f.AwsDoc)
		}
	}

	br := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return 0, fmt.Errorf("batch exec [%d]: %w", i, err)
		}
	}
	if err := br.Close(); err != nil {
		return 0, fmt.Errorf("batch close: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return runID, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
