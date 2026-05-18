package scoring

import "time"

// ─────────────────────────────────────────
// Final Score (최종 통합 위험도)
// ─────────────────────────────────────────
//
// 공식:
//   Final = (0.6 × Global_image + 0.4 × Local) × Toxic_Multiplier
//
//   범위: 0~100 (Toxic=1.0일 때)
//         최대 150 (Toxic=1.5일 때, 추후 작업 B-4)
//
// 의미:
//   "이 Pod의 종합 침해 위험도"
//   - Global (60%): 이미지 자체의 CVE 위험도
//   - Local (40%): Pod의 노출 + 권한 (침해 가능성/영향력)
//   - Toxic: 특정 패턴 매칭 시 증폭 (privileged + secret 등)

// ─────────────────────────────────────────
// 가중치
// ─────────────────────────────────────────

const (
	FinalWeightGlobal = 0.6
	FinalWeightLocal  = 0.4

	// Toxic 미구현 시 기본값
	FinalDefaultToxicMultiplier = 1.0
)

// ─────────────────────────────────────────
// Risk Level
// ─────────────────────────────────────────

const (
	FinalLevelCritical = "Critical" // >= 90
	FinalLevelHigh     = "High"     // >= 70
	FinalLevelMedium   = "Medium"   // >= 40
	FinalLevelLow      = "Low"      // >  0
	FinalLevelNone     = "None"     // == 0
)

// ─────────────────────────────────────────
// 데이터 타입
// ─────────────────────────────────────────

// FinalScoreResult는 단일 Pod의 Final Score 평가 결과입니다.
type FinalScoreResult struct {
	ClusterName  string `json:"cluster_name"`
	PodUID       string `json:"pod_uid"`
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`

	// 종합
	FinalScore float64 `json:"final_score"` // 0~100 (Toxic=1.0)
	RiskLevel  string  `json:"risk_level"`

	// 기여도
	GlobalContribution float64 `json:"global_contribution"`
	LocalContribution  float64 `json:"local_contribution"`
	ToxicMultiplier    float64 `json:"toxic_multiplier"`

	// 원본 점수
	GlobalImageScore float64 `json:"global_image_score"`
	LocalScore       float64 `json:"local_score"`

	// 사용된 이미지
	UsedImageDigest string `json:"used_image_digest,omitempty"`
	UsedImageTag    string `json:"used_image_tag,omitempty"`
	UsedTopCVE      string `json:"used_top_cve,omitempty"`

	// 누락 표시
	MissingGlobalImage bool `json:"missing_global_image,omitempty"`
	MissingLocal       bool `json:"missing_local,omitempty"`
	MissingSBOM        bool `json:"missing_sbom,omitempty"`

	SnapshotAt time.Time `json:"snapshot_at"`
	ComputedAt time.Time `json:"computed_at"`
}

// ─────────────────────────────────────────
// API DTO
// ─────────────────────────────────────────

// FinalComputeRequest는 클러스터 단위 계산 요청입니다.
type FinalComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// FinalComputeResponse는 일괄 계산 결과 요약입니다.
type FinalComputeResponse struct {
	ClusterName string             `json:"cluster_name"`
	SnapshotAt  time.Time          `json:"snapshot_at"`
	Computed    int                `json:"computed"`

	CriticalRisk int `json:"critical_risk"` // >= 90
	HighRisk     int `json:"high_risk"`     // 70~89
	MediumRisk   int `json:"medium_risk"`   // 40~69
	LowRisk      int `json:"low_risk"`      // 1~39

	// 누락 통계
	MissingGlobalImage int `json:"missing_global_image,omitempty"`
	MissingLocal       int `json:"missing_local,omitempty"`
	MissingSBOM        int `json:"missing_sbom,omitempty"`

	Details []FinalScoreResult `json:"details"`
}

// ─────────────────────────────────────────
// 점수 계산
// ─────────────────────────────────────────

// ComputeFinalScore는 가중 평균에 Toxic Multiplier를 곱해 Final Score를 산정합니다.
//
//	globalImage: 이미지의 max_score (0~100), 없으면 0
//	local: local_score (0~100), 없으면 0
//	toxic: toxic multiplier (1.0~1.5), 보통 1.0
//
// 반환:
//	final: 최종 점수
//	globalContrib: global_image × 0.6
//	localContrib:  local × 0.4
func ComputeFinalScore(globalImage, local, toxic float64) (final, globalContrib, localContrib float64) {
	// 범위 보정
	globalImage = clamp(globalImage, 0, 100)
	local = clamp(local, 0, 100)
	if toxic <= 0 {
		toxic = FinalDefaultToxicMultiplier
	}

	globalContrib = globalImage * FinalWeightGlobal
	localContrib = local * FinalWeightLocal

	weightedAvg := globalContrib + localContrib   // 0~100
	final = weightedAvg * toxic                    // 0~150 (toxic 1.5 시)

	// 소수점 2자리
	final = round2Final(final)
	globalContrib = round2Final(globalContrib)
	localContrib = round2Final(localContrib)
	return
}

// ClassifyFinalLevel은 Final Score를 등급으로 분류합니다.
func ClassifyFinalLevel(score float64) string {
	switch {
	case score >= 90:
		return FinalLevelCritical
	case score >= 70:
		return FinalLevelHigh
	case score >= 40:
		return FinalLevelMedium
	case score > 0:
		return FinalLevelLow
	default:
		return FinalLevelNone
	}
}

// clamp는 값을 [min, max] 범위로 보정합니다.
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// round2Final은 소수점 2자리에서 반올림합니다.
func round2Final(x float64) float64 {
	return float64(int(x*100+0.5)) / 100
}
