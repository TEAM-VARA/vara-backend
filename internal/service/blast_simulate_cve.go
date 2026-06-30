package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/edge"
)

// ============================================================================
// CVE → risk 분해 (mc 모드 simulate 전용)
//
// blast 모델에서 p_net(A→B) = B.Risk = final_score(B)/100 이다.
// CVE를 패치하면 B의 Global(이미지 CVE 위험)이 내려가 final_score → B.Risk → 인바운드
// p_net이 비례 감소한다. 이 파일은 그 "패치 후 B.Risk" 비율을 계산해
// attenuateForMitigations에 넘길 cveKeep[podUID] = newRisk/oldRisk 를 만든다.
//
// 정확성 포인트: Global_image = image_global_scores.max_score = "가장 위험한 CVE 점수".
//   - 비-top CVE 제거 → max 불변 → Δ0 (정확).
//   - top CVE 제거    → max = 차순위 CVE 점수(imageMaxGlobalExcluding) → 하락.
//   - 이미지 전체 패치(cve_image) → max = 0.
// final = (0.7·Global + 0.3·Exposure)·Toxic 이므로
//   newFinal = final − 0.7·(Global − newGlobal)·Toxic  (Exposure 역산 불필요).
// ============================================================================

// podRisk — final_scores에서 뽑은 한 파드의 risk 구성요소.
type podRisk struct {
	final  float64 // final_score (0~100)
	global float64 // global_image_score (0~100) = 이미지 max CVE 점수
	toxic  float64 // toxic_multiplier (≥1.0)
	digest string  // used_image_digest
	topCVE string  // used_top_cve (이미지 max를 만든 CVE)
}

// loadPodRisks — 클러스터 파드별 최신 final 구성요소 + image_digest → []podUID 인덱스.
func loadPodRisks(ctx context.Context, pool *pgxpool.Pool, cluster string) (map[string]podRisk, map[string][]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (pod_uid)
		       pod_uid, final_score::float8, global_image_score::float8,
		       toxic_multiplier::float8, COALESCE(used_image_digest,''), COALESCE(used_top_cve,'')
		FROM final_scores
		WHERE cluster_name = $1
		ORDER BY pod_uid, snapshot_at DESC
	`, cluster)
	if err != nil {
		return nil, nil, fmt.Errorf("load pod risks: %w", err)
	}
	defer rows.Close()

	byPod := make(map[string]podRisk)
	byDigest := make(map[string][]string)
	for rows.Next() {
		var uid string
		var p podRisk
		if err := rows.Scan(&uid, &p.final, &p.global, &p.toxic, &p.digest, &p.topCVE); err != nil {
			return nil, nil, fmt.Errorf("scan pod risk: %w", err)
		}
		byPod[uid] = p
		if p.digest != "" {
			byDigest[p.digest] = append(byDigest[p.digest], uid)
		}
	}
	return byPod, byDigest, rows.Err()
}

// riskRatioAfterPatch — newGlobal로 final을 재계산한 newRisk/oldRisk 비율(0~1).
// final = (0.7·global + 0.3·exp)·toxic → newFinal = final − 0.7·(global−newGlobal)·toxic.
func riskRatioAfterPatch(p podRisk, newGlobal float64) float64 {
	if p.final <= 0 {
		return 1 // 이미 risk 0 → p_net도 0, 비율 무의미(불변)
	}
	toxic := p.toxic
	if toxic <= 0 {
		toxic = 1.0
	}
	newFinal := p.final - 0.7*(p.global-newGlobal)*toxic
	if newFinal < 0 {
		newFinal = 0
	}
	r := newFinal / p.final
	if r < 0 {
		r = 0
	}
	if r > 1 {
		r = 1 // 패치가 risk를 올리는 일은 없음
	}
	return r
}

// imageMaxGlobalExcluding — 이미지 CVE 중 excludeCVE를 뺀 max global_score (top CVE 단일 패치용).
// 이미지→CVE 매핑은 GlobalScoringRepo.ReweightAllImages / ListCVEsByImageDigest와 동일
// (Trivy sboms.raw_data ∪ OSV package_vulnerabilities)을 단일 digest로 좁힌 것.
func imageMaxGlobalExcluding(ctx context.Context, pool *pgxpool.Pool, digest, excludeCVE string) (float64, error) {
	const q = `
		WITH img_cve AS (
			SELECT DISTINCT cve_id FROM (
				SELECT vuln->>'VulnerabilityID' AS cve_id
				FROM sboms,
				     jsonb_array_elements(raw_data->'Results') AS result,
				     jsonb_array_elements(COALESCE(result->'Vulnerabilities','[]'::jsonb)) AS vuln
				WHERE image_digest = $1
				  AND raw_data IS NOT NULL AND raw_data::text <> 'null'
				  AND vuln->>'VulnerabilityID' IS NOT NULL AND vuln->>'VulnerabilityID' <> ''
				UNION ALL
				SELECT CASE WHEN pv.vuln_id LIKE 'CVE-%' THEN pv.vuln_id
				            ELSE (SELECT a FROM unnest(pv.aliases) AS a WHERE a LIKE 'CVE-%' LIMIT 1) END AS cve_id
				FROM package_vulnerabilities pv
				JOIN sbom_packages sp ON sp.purl = pv.purl
				WHERE sp.image_digest = $1 AND pv.withdrawn_at IS NULL
			) u
			WHERE cve_id IS NOT NULL AND cve_id LIKE 'CVE-%'
		)
		SELECT COALESCE(MAX(g.global_score::float8), 0)
		FROM img_cve ic
		JOIN cve_global_scores g ON g.cve_id = ic.cve_id
		WHERE ic.cve_id <> $2
	`
	var maxScore float64
	if err := pool.QueryRow(ctx, q, digest, excludeCVE).Scan(&maxScore); err != nil {
		return 0, fmt.Errorf("image max global excluding %s: %w", excludeCVE, err)
	}
	return maxScore, nil
}

// resolveCVEKeep — applied[]의 cve_image/cve_id 조치를 podUID → 인바운드 network 잔존계수로 해석.
//
//	cve_image (target=image_digest 또는 pod_uid) : 이미지 전체 패치 → newGlobal=0
//	cve_id    (target=cve_id)                    : topCVE==target 인 파드만 newGlobal=차순위, 그 외 Δ0(불변)
//
// pool 미주입(s.pool==nil)이거나 final_scores가 없으면 빈 맵(CVE 효과 0). 여러 조치가 같은
// 파드를 치면 잔존계수를 곱한다(누적 패치). Effectiveness는 1−eff 만큼만 적용한다(부분 패치).
func (s *EdgeService) resolveCVEKeep(ctx context.Context, cluster string, applied []edge.AppliedMitigation) (map[string]float64, error) {
	// CVE 조치가 하나도 없으면 DB 조회 생략.
	hasCVE := false
	for _, m := range applied {
		if m.Kind == "cve_image" || m.Kind == "cve_id" {
			hasCVE = true
			break
		}
	}
	if !hasCVE || s.pool == nil {
		return nil, nil
	}

	byPod, byDigest, err := loadPodRisks(ctx, s.pool, cluster)
	if err != nil {
		return nil, err
	}

	keep := make(map[string]float64)
	// applyKeep — 부분 패치(eff<1)면 잔존계수를 newRisk와 원본(1.0) 사이로 보간.
	applyKeep := func(uid string, ratio float64, eff *float64) {
		e := 1.0
		if eff != nil && *eff >= 0 && *eff <= 1 {
			e = *eff
		}
		// 완전 패치면 ratio, 부분이면 1 − e·(1−ratio) (eff=1→ratio, eff=0→1.0).
		k := 1 - e*(1-ratio)
		if cur, ok := keep[uid]; ok {
			k *= cur // 여러 조치 누적
		}
		keep[uid] = k
	}

	for _, m := range applied {
		switch m.Kind {
		case "cve_image":
			// target = image_digest 우선. pod_uid면 그 파드의 digest로 풀어
			// 같은 이미지를 쓰는 파드(image-shared) 전부를 패치 대상으로 잡는다.
			// (시나리오 응답에 image_digest가 비어 FE가 pod_uid로 폴백해도 동작)
			uids := byDigest[m.Target]
			if len(uids) == 0 {
				if p, ok := byPod[m.Target]; ok {
					if p.digest != "" {
						uids = byDigest[p.digest] // 같은 image_digest 쓰는 파드 전부
					}
					if len(uids) == 0 {
						uids = []string{m.Target} // digest 미상이면 그 파드만
					}
				}
			}
			for _, uid := range uids {
				ratio := riskRatioAfterPatch(byPod[uid], 0) // 이미지 전체 패치 → global 0
				applyKeep(uid, ratio, m.Effectiveness)
			}
		case "cve_id":
			// 이 CVE가 이미지 max(topCVE)인 파드만 영향. 차순위로 global 재계산.
			for uid, p := range byPod {
				if p.topCVE != m.Target || p.digest == "" {
					continue // 비-top CVE 제거는 max 불변 → Δ0
				}
				newGlobal, err := imageMaxGlobalExcluding(ctx, s.pool, p.digest, m.Target)
				if err != nil {
					return nil, err
				}
				ratio := riskRatioAfterPatch(p, newGlobal)
				applyKeep(uid, ratio, m.Effectiveness)
			}
		}
	}
	return keep, nil
}
