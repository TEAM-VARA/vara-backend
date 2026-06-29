package scoring

import "time"

// ─────────────────────────────────────────
// Final Score (최종 통합 위험도)
// ─────────────────────────────────────────
//
// 공식:
//   Final = (0.7 × Global_image + 0.3 × Exposure) × Toxic_Multiplier
//
//   Risk Score는 "발생 가능성(likelihood)"만 다룬다:
//     - Global   : CVE 자체의 본질적 위험
//     - Exposure : 인터넷 노출 (0=비노출, 100=노출)
//   Attack Path(RBAC/Network/Mount)는 "영향(impact)" 축이라 Risk Score에서 제외하고
//   자산중요도·Blast Radius로 분리 표기한다. (attack_path 계산/테이블/API는 유지)
//
//   범위: 0~100 (상한 clamp)

// ─────────────────────────────────────────
// 가중치
// ─────────────────────────────────────────

const (
	FinalWeightGlobal   = 0.7
	FinalWeightExposure = 0.3

	FinalDefaultToxicMultiplier = 1.0
)

// ─────────────────────────────────────────
// Risk Level (4단계, 영문 식별자 + 한글 라벨)
// ─────────────────────────────────────────
//
// 임계값:
//   emergency : score >= 90
//   warning   : score >= 70
//   caution   : score >= 40
//   safe      : score < 40

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
//   emergency_count : >= 90
//   warning_count   : >= 70
//   caution_count   : >= 40
//   safe_count      : < 40
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

// ─────────────────────────────────────────
// Score Breakdown (점수 구성 분해 + 설명)
// ─────────────────────────────────────────

// ScoreBreakdown은 Final Score의 구성과 각 항목의 의미·해석을 담습니다.
type ScoreBreakdown struct {
	PodUID     string  `json:"pod_uid"`
	PodName    string  `json:"pod_name"`
	FinalScore float64 `json:"final_score"`
	RiskLevel  string  `json:"risk_level"`
	RiskLabel  string  `json:"risk_label"`

	Global BreakdownSection `json:"global"`
	Local  BreakdownSection `json:"local"`
	Toxic  BreakdownSection `json:"toxic"`

	// ISMSP는 FinalScore에 더해진 ISMS-P 미준수 가산 내역이다.
	// 가산이 없으면(addend=0) nil → JSON에서 생략(omitempty)된다.
	// FinalScore에는 이 가산이 이미 포함되어 있으므로, Global+Local 기여도 합과
	// FinalScore의 차이가 곧 이 ISMSP.Addend다.
	ISMSP *BreakdownISMSP `json:"ismsp,omitempty"`

	Formula string `json:"formula"`
}

// BreakdownISMSP는 Score Breakdown에 표기할 ISMS-P 미준수 가산 섹션이다.
// (service.ISMSPRiskBreakdown의 표시용 사본 — domain은 service를 import하지 않으므로 별도 정의)
type BreakdownISMSP struct {
	Label          string               `json:"label"`           // "ISMS-P 미준수 가산"
	Addend         float64              `json:"addend"`          // FinalScore에 더해진 총합(상3+중2+하1)
	CountHigh      int                  `json:"count_high"`      // 상 건수
	CountMedium    int                  `json:"count_medium"`    // 중 건수
	CountLow       int                  `json:"count_low"`       // 하 건수
	Description    string               `json:"description"`     // 항목 정의(고정)
	Interpretation string               `json:"interpretation"`  // 값별 해석
	Rules          []BreakdownISMSPRule `json:"rules,omitempty"` // 가산된 룰 목록
}

// BreakdownISMSPRule은 가산에 기여한 개별 ISMS-P 룰이다.
type BreakdownISMSPRule struct {
	RuleID    string  `json:"rule_id"`
	Severity  string  `json:"severity"`  // 상/중/하
	Weight    float64 `json:"weight"`    // 3/2/1
	Inherited bool    `json:"inherited"` // 계정/클러스터 공통 결함(상속) 투영분
}

// BreakdownSection은 한 항목(Global/Local/Toxic)의 점수·설명·해석·세부요인입니다.
type BreakdownSection struct {
	Label          string            `json:"label"`             // "Global Score"
	RawScore       float64           `json:"raw_score"`          // 원점수 (Toxic은 multiplier)
	Weight         float64           `json:"weight,omitempty"`  // 0.7 / 0.3 (Toxic 없음)
	Contribution   float64           `json:"contribution"`      // 가중 기여분
	Description    string            `json:"description"`       // 항목 정의 (고정)
	Interpretation string            `json:"interpretation"`    // 값별 해석 (다)
	Factors        []BreakdownFactor `json:"factors,omitempty"` // 세부 지표
}

// BreakdownFactor는 항목 내 개별 지표(CVSS, EPSS, exposure 등)입니다.
type BreakdownFactor struct {
	Name           string `json:"name"`           // "CVSS"
	Value          string `json:"value"`          // "9.8 (CRITICAL)"
	Description    string `json:"description"`    // 지표 정의 (고정)
	Interpretation string `json:"interpretation"` // 값별 해석 (다)
}

type BreakdownGlobal struct {
	RawScore     float64 `json:"raw_score"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	TopCVE       string  `json:"top_cve,omitempty"`
}

type BreakdownLocal struct {
	RawScore     float64 `json:"raw_score"`
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
//
// 두 번째 인자 exposure는 인터넷 노출 점수(0~100)입니다.
// (예전엔 local = exposure+attack_path였으나, attack_path를 제외하고 exposure만 사용)
func ComputeFinalScore(globalImage, exposure, toxic float64) (final, globalContrib, exposureContrib float64) {
	globalImage = clamp(globalImage, 0, 100)
	exposure = clamp(exposure, 0, 100)
	if toxic <= 0 {
		toxic = FinalDefaultToxicMultiplier
	}

	// 가중치는 전역 설정(CurrentWeights)에서 읽는다. 미설정 시 기본값(0.7/0.3).
	w := CurrentWeights()
	globalContrib = globalImage * w.FinalGlobal
	exposureContrib = exposure * w.FinalExposure

	weightedAvg := globalContrib + exposureContrib
	final = weightedAvg * toxic

	final = clamp(final, 0, 100)

	final = round2Final(final)
	globalContrib = round2Final(globalContrib)
	exposureContrib = round2Final(exposureContrib)
	return
}

// ClassifyFinalLevel은 Final Score를 영문 등급 식별자로 분류합니다.
//
// 컷은 전역 설정(CurrentWeights)에서 읽는다 (기본 75/50/25):
//
//	score >= CutEmergency → "emergency" (긴급)
//	score >= CutWarning   → "warning"   (경고)
//	score >= CutCaution   → "caution"   (주의)
//	score <  CutCaution   → "safe"      (안전)
func ClassifyFinalLevel(score float64) string {
	w := CurrentWeights()
	switch {
	case score >= w.CutEmergency:
		return FinalLevelEmergency
	case score >= w.CutWarning:
		return FinalLevelWarning
	case score >= w.CutCaution:
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
