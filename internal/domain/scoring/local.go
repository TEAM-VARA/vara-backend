package scoring

import "time"

// ─────────────────────────────────────────
// Local Score (Pod 단위 위험도 통합)
// ─────────────────────────────────────────
//
// 두 가지 위험 신호를 통합:
//   1. 인터넷 노출 (작업 C-1): exposed 여부 (0 또는 20)
//   2. 공격 경로 범위 (작업 B-2c): RBAC + Network + Mount (0~100)
//
// 공식:
//   Local Score = exposure_contribution(0~20) + attack_path_contribution(0~80)
//   여기서 attack_path_contribution = (attack_path_total / 100) × 80
//
// 의미:
//   exposure는 "공격 가능성 여부"
//   attack_path는 "공격 성공 시 영향 범위"
//   둘이 결합 시 실질적 위험도.

// ─────────────────────────────────────────
// 가중치
// ─────────────────────────────────────────

const (
	LocalMaxExposure   = 20.0
	LocalMaxAttackPath = 80.0
	LocalMaxTotal      = LocalMaxExposure + LocalMaxAttackPath // 100.0
)

// ─────────────────────────────────────────
// Local Risk Level (4단계, 영문 식별자 + 한글 라벨)
// ─────────────────────────────────────────
//
// 임계값 (Final과 동일):
//   emergency : score >= 90
//   warning   : score >= 70
//   caution   : score >= 40
//   safe      : score <  40

const (
	LocalLevelEmergency = "emergency" // 긴급
	LocalLevelWarning   = "warning"   // 경고
	LocalLevelCaution   = "caution"   // 주의
	LocalLevelSafe      = "safe"      // 안전
)

var localLevelLabels = map[string]string{
	LocalLevelEmergency: "긴급",
	LocalLevelWarning:   "경고",
	LocalLevelCaution:   "주의",
	LocalLevelSafe:      "안전",
}

// LocalLevelLabel returns the Korean display label for a local risk level.
func LocalLevelLabel(level string) string {
	return localLevelLabels[level]
}

// ─────────────────────────────────────────
// 데이터 타입
// ─────────────────────────────────────────

// LocalScoreResult는 단일 Pod의 Local Score 평가 결과입니다.
type LocalScoreResult struct {
	// 식별
	ClusterName  string `json:"cluster_name"`
	PodUID       string `json:"pod_uid"`
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`

	// 종합 점수
	LocalScore float64 `json:"local_score"` // 0~100
	LocalLevel string  `json:"local_level"` // emergency/warning/caution/safe
	LocalLabel string  `json:"local_label"` // 긴급/경고/주의/안전

	// 항목별 기여도
	ExposureContribution   float64 `json:"exposure_contribution"`    // 0~20
	AttackPathContribution float64 `json:"attack_path_contribution"` // 0~80

	// 원본 점수
	ExposureScoreRaw   int `json:"exposure_score_raw"`    // 0 또는 20
	AttackPathScoreRaw int `json:"attack_path_score_raw"` // 0~100

	// 핵심 신호
	Exposed         bool   `json:"exposed"`
	AttackPathLevel string `json:"attack_path_level"`

	// 시점
	SnapshotAt time.Time `json:"snapshot_at"`
	ComputedAt time.Time `json:"computed_at"`
}

// ─────────────────────────────────────────
// API DTO
// ─────────────────────────────────────────

// LocalComputeRequest는 클러스터 단위 계산 요청입니다.
type LocalComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// LocalComputeResponse는 일괄 계산 결과 요약입니다.
//
// 카운트 필드 (4단계):
//   emergency_count : >= 90
//   warning_count   : >= 70
//   caution_count   : >= 40
//   safe_count      : <  40
type LocalComputeResponse struct {
	ClusterName    string             `json:"cluster_name"`
	SnapshotAt     time.Time          `json:"snapshot_at"`
	Computed       int                `json:"computed"`
	EmergencyCount int                `json:"emergency_count"`
	WarningCount   int                `json:"warning_count"`
	CautionCount   int                `json:"caution_count"`
	SafeCount      int                `json:"safe_count"`
	Details        []LocalScoreResult `json:"details"`

	// 누락 데이터 경고
	MissingExposure   int `json:"missing_exposure,omitempty"`    // exposure 점수 없는 Pod 수
	MissingAttackPath int `json:"missing_attack_path,omitempty"` // attack_path 점수 없는 Pod 수
}

// ─────────────────────────────────────────
// 점수 계산
// ─────────────────────────────────────────

// ComputeLocalScore는 두 원본 점수로부터 Local Score를 산정합니다.
//
//	exposureRaw:   인터넷 노출 점수 원본 (0 또는 20)
//	attackPathRaw: 공격 경로 범위 점수 원본 (0~100)
//
// 반환:
//	localScore: 0~100
//	exposureContribution: 0~20
//	attackPathContribution: 0~80
func ComputeLocalScore(exposureRaw, attackPathRaw int) (localScore, exposureContribution, attackPathContribution float64) {
	exposureContribution = float64(exposureRaw)
	if exposureContribution > LocalMaxExposure {
		exposureContribution = LocalMaxExposure
	}
	if exposureContribution < 0 {
		exposureContribution = 0
	}

	apRaw := float64(attackPathRaw)
	if apRaw > 100 {
		apRaw = 100
	}
	if apRaw < 0 {
		apRaw = 0
	}
	attackPathContribution = apRaw * LocalMaxAttackPath / 100.0

	localScore = exposureContribution + attackPathContribution
	if localScore > LocalMaxTotal {
		localScore = LocalMaxTotal
	}

	localScore = round2(localScore)
	exposureContribution = round2(exposureContribution)
	attackPathContribution = round2(attackPathContribution)

	return
}

// ClassifyLocalLevel은 Local Score를 영문 등급 식별자로 분류합니다.
//
//	score >= 90 → "emergency" (긴급)
//	score >= 70 → "warning"   (경고)
//	score >= 40 → "caution"   (주의)
//	score <  40 → "safe"      (안전)
func ClassifyLocalLevel(score float64) string {
	switch {
	case score >= 90:
		return LocalLevelEmergency
	case score >= 70:
		return LocalLevelWarning
	case score >= 40:
		return LocalLevelCaution
	default:
		return LocalLevelSafe
	}
}

// round2는 소수점 2자리에서 반올림합니다.
func round2(x float64) float64 {
	return float64(int(x*100+0.5)) / 100
}
