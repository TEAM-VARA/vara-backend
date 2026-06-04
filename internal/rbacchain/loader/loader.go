// Package loader — RBAC 분석 입력 snapshot 을 만드는 어댑터.
//
// 엔진(directperm/fixpoint/sareport)은 snapshot(map[string]any)만 받는다.
// 그 snapshot 을 "어디서" 만드느냐를 이 패키지가 추상화한다:
//
//	PostgresLoader — vara DB 에서 pin 된 시점을 메모리로 직접 로드 (운영 경로, 파일 없음)
//	JSONDirLoader  — dbeaver_export JSON 폴더에서 로드 (오프라인/테스트/parity)
//
// 두 로더 모두 BuildSnapshotFromRaw 라는 동일한 변환부를 통과하므로 결과가 동치다.
package loader

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SnapshotLoader — cluster 이름을 받아 분석용 snapshot 을 만든다.
type SnapshotLoader interface {
	Load(ctx context.Context, cluster string) (map[string]any, error)
}

// ----------------------------------------------------------------------------
// JSONDirLoader — dbeaver_export 폴더 기반 (오프라인/테스트).
// ----------------------------------------------------------------------------

type JSONDirLoader struct {
	Dir string // dbeaver_export 디렉토리
}

func NewJSONDirLoader(dir string) *JSONDirLoader { return &JSONDirLoader{Dir: dir} }

func (l *JSONDirLoader) Load(_ context.Context, cluster string) (map[string]any, error) {
	snap, _, err := BuildSnapshot(l.Dir, cluster)
	if err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, fmt.Errorf("rbacchain: cluster %q: RBAC 5종 공통 snapshot_at 없음 (dir=%s)", cluster, l.Dir)
	}
	return snap, nil
}

// ----------------------------------------------------------------------------
// PostgresLoader — vara DB 직접 (운영 경로).
//
// 3-pin 정책 (from_vara_db.go 와 동일):
//   - RBAC 5종: 5개 테이블 모두에 row 가 있는 가장 최근 공통 snapshot_at
//   - cluster_pods / cluster_nodes: 각자 MAX(snapshot_at)
//
// pin 된 row 만 SELECT 해서 메모리 snapshot 으로 변환 (디스크 파일 없음).
// ----------------------------------------------------------------------------

type PostgresLoader struct {
	pool *pgxpool.Pool
}

func NewPostgresLoader(pool *pgxpool.Pool) *PostgresLoader { return &PostgresLoader{pool: pool} }

// RBAC 5종 공통 최신 snapshot_at. 공통이 없으면 NULL 반환.
const rbacCommonPinSQL = `
WITH common AS (
    SELECT snapshot_at FROM cluster_service_accounts      WHERE cluster_name = $1
    INTERSECT
    SELECT snapshot_at FROM cluster_cluster_roles         WHERE cluster_name = $1
    INTERSECT
    SELECT snapshot_at FROM cluster_roles                 WHERE cluster_name = $1
    INTERSECT
    SELECT snapshot_at FROM cluster_cluster_role_bindings WHERE cluster_name = $1
    INTERSECT
    SELECT snapshot_at FROM cluster_role_bindings         WHERE cluster_name = $1
)
SELECT MAX(snapshot_at) FROM common`

func (l *PostgresLoader) Load(ctx context.Context, cluster string) (map[string]any, error) {
	rbacAt, err := l.scanMaxTime(ctx, rbacCommonPinSQL, cluster)
	if err != nil {
		return nil, fmt.Errorf("rbacchain: RBAC pin 조회 실패: %w", err)
	}
	if rbacAt == nil {
		return nil, fmt.Errorf("rbacchain: cluster %q: RBAC 5종 모두에 row 가 있는 공통 snapshot_at 이 없음", cluster)
	}
	podsAt, err := l.scanMaxTime(ctx, `SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1`, cluster)
	if err != nil {
		return nil, fmt.Errorf("rbacchain: cluster_pods pin 조회 실패: %w", err)
	}
	nodesAt, err := l.scanMaxTime(ctx, `SELECT MAX(snapshot_at) FROM cluster_nodes WHERE cluster_name = $1`, cluster)
	if err != nil {
		return nil, fmt.Errorf("rbacchain: cluster_nodes pin 조회 실패: %w", err)
	}

	rawTables := map[string][]any{}

	// RBAC 5종 @ rbacAt
	for _, t := range DBJRBACTables {
		rows, err := l.queryRowMaps(ctx,
			"SELECT * FROM "+t+" WHERE cluster_name = $1 AND snapshot_at = $2", cluster, *rbacAt)
		if err != nil {
			return nil, fmt.Errorf("rbacchain: dump %s 실패: %w", t, err)
		}
		rawTables[t] = rows
	}

	// pods / nodes @ 각자 MAX (없으면 빈 목록)
	rawTables["cluster_pods"] = []any{}
	if podsAt != nil {
		rows, err := l.queryRowMaps(ctx,
			"SELECT * FROM cluster_pods WHERE cluster_name = $1 AND snapshot_at = $2", cluster, *podsAt)
		if err != nil {
			return nil, fmt.Errorf("rbacchain: dump cluster_pods 실패: %w", err)
		}
		rawTables["cluster_pods"] = rows
	}
	rawTables["cluster_nodes"] = []any{}
	if nodesAt != nil {
		rows, err := l.queryRowMaps(ctx,
			"SELECT * FROM cluster_nodes WHERE cluster_name = $1 AND snapshot_at = $2", cluster, *nodesAt)
		if err != nil {
			return nil, fmt.Errorf("rbacchain: dump cluster_nodes 실패: %w", err)
		}
		rawTables["cluster_nodes"] = rows
	}

	snap, _, err := BuildSnapshotFromRaw(rawTables, cluster)
	if err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, fmt.Errorf("rbacchain: cluster %q: snapshot 생성 실패 (공통 시점 불일치)", cluster)
	}
	return snap, nil
}

// scanMaxTime — MAX(snapshot_at) 한 값 조회. row 없거나 NULL 이면 nil 반환.
func (l *PostgresLoader) scanMaxTime(ctx context.Context, sql, cluster string) (*time.Time, error) {
	var at *time.Time
	if err := l.pool.QueryRow(ctx, sql, cluster).Scan(&at); err != nil {
		return nil, err
	}
	return at, nil
}

// queryRowMaps — SELECT 결과를 컬럼명 키 dict 목록으로. 값은 normalizeValue 로
// DBeaver export 와 동일 표현으로 변환 (jsonb 디코드, timestamp ISO 문자열 등).
func (l *PostgresLoader) queryRowMaps(ctx context.Context, sql string, args ...any) ([]any, error) {
	rows, err := l.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	desc := rows.FieldDescriptions()
	out := []any{}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		m := make(map[string]any, len(desc))
		for i, fd := range desc {
			m[string(fd.Name)] = normalizeValue(vals[i])
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
