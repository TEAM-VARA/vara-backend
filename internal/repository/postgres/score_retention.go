package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ScoreRetentionRepo는 점수 스냅샷 테이블들을 최신 snapshot만 남기고 정리합니다
// (엣지의 DeleteEdgesBefore와 동일한 retention 방식).
type ScoreRetentionRepo struct {
	pool *pgxpool.Pool
}

func NewScoreRetentionRepo(pool *pgxpool.Pool) *ScoreRetentionRepo {
	return &ScoreRetentionRepo{pool: pool}
}

// PruneOldSnapshots는 각 점수 테이블에서 cluster의 최신 snapshot_at(MAX) 미만인 행을
// 전부 삭제합니다. 최신 snapshot은 < MAX 조건에 걸리지 않으므로 이번 사이클 결과는 보존됩니다.
// 한 테이블에서 에러가 나도 나머지 테이블은 계속 처리하며, 첫 에러만 반환합니다.
func (r *ScoreRetentionRepo) PruneOldSnapshots(ctx context.Context, cluster string) (int64, error) {
	// 코드 상수 배열이라 SQL injection 위험 없음 — fmt.Sprintf OK.
	tables := []string{"final_scores", "exposure_scores", "attack_path_scores", "local_scores", "toxic_results"}
	var total int64
	var firstErr error
	for _, t := range tables {
		q := fmt.Sprintf("DELETE FROM %s WHERE cluster_name=$1 AND snapshot_at < (SELECT MAX(snapshot_at) FROM %s WHERE cluster_name=$1)", t, t)
		tag, err := r.pool.Exec(ctx, q, cluster)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		total += tag.RowsAffected()
	}
	return total, firstErr
}
