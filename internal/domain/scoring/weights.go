package scoring

import "sync/atomic"

// Weights는 Risk Scoring 전역 가중치 설정입니다 (scoring_weights 단일행에 대응).
//
// 점수 계산(ComputeFinalScore/ComputeGlobalScore/EvaluateToxic)은 CurrentWeights()를 통해
// 이 값을 읽는다. 서버 기동 시 DB값으로 SetWeights, 대시보드 PUT 시에도 SetWeights.
type Weights struct {
	FinalGlobal   float64 `json:"final_weight_global"`
	FinalExposure float64 `json:"final_weight_exposure"`

	GlobalCVSS float64 `json:"global_weight_cvss"`
	GlobalEPSS float64 `json:"global_weight_epss"`
	GlobalSSVC float64 `json:"global_weight_ssvc"`

	ToxicCritical float64 `json:"toxic_critical"`
	ToxicHigh     float64 `json:"toxic_high"`
	ToxicMedium   float64 `json:"toxic_medium"`
}

// DefaultWeights는 코드 기본값입니다 (DB 미설정/로드 실패 시 폴백).
func DefaultWeights() Weights {
	return Weights{
		FinalGlobal:   FinalWeightGlobal,
		FinalExposure: FinalWeightExposure,
		GlobalCVSS:    GlobalWeightCVSS,
		GlobalEPSS:    GlobalWeightEPSS,
		GlobalSSVC:    GlobalWeightSSVC,
		ToxicCritical: 1.5,
		ToxicHigh:     1.3,
		ToxicMedium:   1.2,
	}
}

// currentWeights는 race-safe 전역 현재 가중치. 미설정 시 DefaultWeights로 폴백.
var currentWeights atomic.Pointer[Weights]

// SetWeights는 전역 현재 가중치를 갱신합니다 (race-safe). 서버 기동·가중치 PUT 시 호출.
func SetWeights(w Weights) {
	currentWeights.Store(&w)
}

// CurrentWeights는 현재 적용 중인 가중치를 반환합니다. 미설정 시 DefaultWeights.
func CurrentWeights() Weights {
	if p := currentWeights.Load(); p != nil {
		return *p
	}
	return DefaultWeights()
}

// ToxicMultiplierForSeverity는 Severity(Critical/High/Medium)에 해당하는 설정 배수를 반환합니다.
// 그 외(또는 미매칭)는 1.0.
func (w Weights) ToxicMultiplierForSeverity(severity string) float64 {
	switch severity {
	case "Critical":
		return w.ToxicCritical
	case "High":
		return w.ToxicHigh
	case "Medium":
		return w.ToxicMedium
	}
	return 1.0
}
