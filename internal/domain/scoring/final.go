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
//         최대 150 (Toxic=1.5일 때, 작업 B-4 매칭 시)

// ─────────────────────────────────────────
// 가중치
// ─────────────────────────────────────────

const (
	FinalWeightGlobal = 0.6
	FinalWeightLocal  = 0.4

	FinalDefaultToxicMultiplier = 1.0
)

// ─────────────────────────────────────────
// Risk Level (4단계, 영문 식별자 + 한글 라벨)
// ─────────────────────────────────────────
//
// 임계값:
//   emergency : score >= 80
//   warning   : score >= 50
//   caution   : score >= 20
//   safe      : score < 20

const (
	FinalLevelEmergency = "emergency" // 긴급
	FinalLevelWarning   = "warning"   // 경고
	FinalLevelCaution   = "caution"   // 주의
	FinalLevelSafe      = "safe"      // 안전
)

// Korean labels for risk levels.
var finalLevelLabels = map[string]string{
	FinalLevelEmergency: "긴급",
	FinalLevelWarning:   "경고",
	FinalLevelCaution:   "주의",
	FinalLevelSafe:      "안전",
}

// FinalLevelLabel returns the Korean display label for a risk level identifier.
// Returns empty string if the identifier is unknown.
func FinalLevelLabel(level string) string {
	return finalLevelLabels[level]
}

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
	RiskLevel  string  `json:"risk_level"`  // emergency/warning/caution/safe
	RiskLabel  string  `json:"risk_label"`  // 긴급/경고/주의/안전

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
//
// 카운트 필드 (4단계):
//   emergency_count : >= 80
//   warning_count   : >= 50
//   caution_count   : >= 20
//   safe_count      : < 20
type FinalComputeResponse struct {
	ClusterName string    `json:"cluster_name"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	Computed    int       `json:"computed"`

	EmergencyCount int `json:"emergency_count"` // 긴급
	WarningCount   int `json:"warning_count"`   // 경고
	CautionCount   int `json:"caution_count"`   // 주의
	SafeCount      int `json:"safe_count"`      // 안전

	// 누락 통계
	MissingGlobalImage int `json:"missing_global_image,omitempty"`
	MissingLocal       int `json:"missing_local,omitempty"`
	MissingSBOM        int `json:"missing_sbom,omitempty"`

	Details []FinalScoreResult `json:"details"`
}

// ScoreBreakdown은 Final Score의 구성 근거를 분해한 응답입니다.
type ScoreBreakdown struct {
	PodUID     string  `json:"podUid"`
	PodName    string  `json:"podName"`
	FinalScore float64 `json:"finalScore"`
	RiskLevel  string  `json:"riskLevel"`
	RiskLabel  string  `json:"riskLabel"`

	Global BreakdownGlobal `json:"global"`
	Local  BreakdownLocal  `json:"local"`
	Toxic  BreakdownToxic  `json:"toxic"`

	Formula string `json:"formula"`
}

type BreakdownGlobal struct {
	RawScore     float64 `json:"rawScore"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	TopCVE       string  `json:"topCve,omitempty"`
}

type BreakdownLocal struct {
	RawScore     float64 `json:"rawScore"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

type BreakdownToxic struct {
	Multiplier float64 `json:"multiplier"`
}

// ─────────────────────────────────────────
// 점수 계산
// ─────────────────────────────────────────

// ComputeFinalScore는 가중 평균에 Toxic Multiplier를 곱해 Final Score를 산정합니다.
func ComputeFinalScore(globalImage, local, toxic float64) (final, globalContrib, localContrib float64) {
	globalImage = clamp(globalImage, 0, 100)
	local = clamp(local, 0, 100)
	if toxic <= 0 {
		toxic = FinalDefaultToxicMultiplier
	}

	globalContrib = globalImage * FinalWeightGlobal
	localContrib = local * FinalWeightLocal

	weightedAvg := globalContrib + localContrib
	final = weightedAvg * toxic

	final = round2Final(final)
	globalContrib = round2Final(globalContrib)
	localContrib = round2Final(localContrib)
	return
}

// ClassifyFinalLevel은 Final Score를 영문 등급 식별자로 분류합니다.
//
//	score >= 80 → "emergency" (긴급)
//	score >= 50 → "warning"   (경고)
//	score >= 20 → "caution"   (주의)
//	score <  20 → "safe"      (안전)
func ClassifyFinalLevel(score float64) string {
	switch {
	case score >= 80:
		return FinalLevelEmergency
	case score >= 50:
		return FinalLevelWarning
	case score >= 20:
		return FinalLevelCaution
	default:
		return FinalLevelSafe
	}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round2Final(x float64) float64 {
	return float64(int(x*100+0.5)) / 100
}
