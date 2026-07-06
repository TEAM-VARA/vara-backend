package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/agent"
	"github.com/vara/backend/internal/domain/scoring"
)

type ScoringRepo struct {
	pg *pgxpool.Pool
}

func NewScoringRepo(pg *pgxpool.Pool) *ScoringRepo {
	return &ScoringRepo{pg: pg}
}

// GetPodInfo : pod_id로 Pod 정보 + 연결된 CVE 조회
func (r *ScoringRepo) GetPodInfo(ctx context.Context, podID string) (*agent.PodInfo, error) {
	const podQ = `
		SELECT pod_uid, pod_name, namespace, image, image_digest
		FROM pods
		WHERE pod_uid = $1
	`
	row := r.pg.QueryRow(ctx, podQ, podID)
	info := &agent.PodInfo{}
	err := row.Scan(&info.PodID, &info.PodName, &info.Namespace, &info.ImageName, &info.RuntimeDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}

	const buildQ = `
		SELECT image_digest FROM sboms WHERE image = $1
		ORDER BY created_at DESC LIMIT 1
	`
	var buildDigest string
	if err := r.pg.QueryRow(ctx, buildQ, info.ImageName).Scan(&buildDigest); err == nil {
		info.BuildDigest = buildDigest
	}

	const cveQ = `
		SELECT DISTINCT cve_id FROM cves
		WHERE image_digest = $1
	`
	rows, err := r.pg.Query(ctx, cveQ, info.RuntimeDigest)
	if err != nil {
		return info, nil
	}
	defer rows.Close()

	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err == nil {
			info.CVEList = append(info.CVEList, cveID)
		}
	}

	return info, nil
}

// SaveScoring : 계산된 점수를 DB에 저장
func (r *ScoringRepo) SaveScoring(
	ctx context.Context,
	podID string,
	imageName string,
	imageDigest string,
	result scoring.Result,
	details []scoring.CVEDetail,
	digestCheck *scoring.DigestCheckDetail,
	ismspRisk *scoring.ISMSPRisk,
) error {
	resultJSON, _ := json.Marshal(result)
	detailsJSON, _ := json.Marshal(details)
	var digestJSON []byte
	if digestCheck != nil {
		digestJSON, _ = json.Marshal(digestCheck)
	}
	var ismspJSON []byte
	if ismspRisk != nil {
		ismspJSON, _ = json.Marshal(ismspRisk)
	}

	const q = `
		INSERT INTO risk_scoring_results
		  (pod_id, image_name, image_digest, result_json, details_json, digest_check_json, ismsp_risk_json, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (pod_id) DO UPDATE SET
		  image_name = EXCLUDED.image_name,
		  image_digest = EXCLUDED.image_digest,
		  result_json = EXCLUDED.result_json,
		  details_json = EXCLUDED.details_json,
		  digest_check_json = EXCLUDED.digest_check_json,
		  ismsp_risk_json = EXCLUDED.ismsp_risk_json,
		  computed_at = EXCLUDED.computed_at
	`
	_, err := r.pg.Exec(ctx, q,
		podID, imageName, imageDigest,
		resultJSON, detailsJSON, digestJSON, ismspJSON,
		time.Now(),
	)
	return err
}

// GetScoring : 저장된 점수 조회
func (r *ScoringRepo) GetScoring(ctx context.Context, podID string) (*scoring.DetailsResponse, error) {
	const q = `
		SELECT image_name, image_digest, result_json, details_json, digest_check_json, ismsp_risk_json, computed_at
		FROM risk_scoring_results
		WHERE pod_id = $1
	`
	var imageName, imageDigest string
	var resultJSON, detailsJSON, digestJSON, ismspJSON []byte
	var computedAt time.Time

	err := r.pg.QueryRow(ctx, q, podID).Scan(
		&imageName, &imageDigest,
		&resultJSON, &detailsJSON, &digestJSON, &ismspJSON,
		&computedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}

	resp := &scoring.DetailsResponse{
		PodID:       podID,
		ImageName:   imageName,
		ImageDigest: imageDigest,
		ComputedAt:  computedAt,
	}
	json.Unmarshal(resultJSON, &resp.Result)
	json.Unmarshal(detailsJSON, &resp.Details)
	if len(digestJSON) > 0 {
		var dc scoring.DigestCheckDetail
		if err := json.Unmarshal(digestJSON, &dc); err == nil {
			resp.DigestCheck = &dc
		}
	}
	if len(ismspJSON) > 0 {
		var ir scoring.ISMSPRisk
		if err := json.Unmarshal(ismspJSON, &ir); err == nil {
			resp.ISMSPRisk = &ir
		}
	}
	return resp, nil
}
