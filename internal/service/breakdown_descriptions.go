package service

import "fmt"

// ─────────────────────────────────────────
// 항목 정의 (고정 텍스트)
// 팀에서 워딩 다듬을 때 이 파일만 수정하면 됩니다.
// ─────────────────────────────────────────

const (
	descGlobal = "이 Pod이 사용하는 컨테이너 이미지에 포함된 알려진 취약점(CVE)의 위험도입니다. " +
		"취약점의 심각도(CVSS), 악용 확률(EPSS), 실제 악용 여부(KEV/SSVC)를 종합합니다."
	descLocal = "이 Pod이 실제 클러스터에서 처한 환경적 위험도입니다. " +
		"외부 노출 여부와 침해 시 공격 확산 가능성을 종합합니다 (노출 20% + 공격경로 80%)."
	descToxic = "여러 위험 요소가 동시에 존재할 때 위험을 증폭시키는 배수입니다. " +
		"예를 들어 '실제 악용되는 취약점 + 외부 노출'이 겹치면 단순 합산보다 위험이 커집니다."

	descCVSS       = "취약점 자체의 기술적 심각도를 0~10으로 나타낸 표준 점수입니다."
	descEPSS       = "이 취약점이 향후 30일 내 실제로 악용될 확률입니다."
	descKEV        = "미국 CISA가 '실제 공격에 사용 중'으로 공식 확인한 취약점 목록입니다."
	descSSVC       = "취약점의 악용 단계 분류입니다 (active=악용 중, poc=개념증명 존재, none=없음)."
	descExposure   = "이 Pod이 클러스터 외부에서 직접 접근 가능한지 여부입니다 (LoadBalancer, Ingress 등)."
	descAttackPath = "이 Pod이 침해됐을 때 권한 상승이나 다른 자원으로의 횡적 이동이 " +
		"얼마나 쉬운지를 평가합니다 (RBAC 권한, 볼륨 마운트, 네트워크 격리)."
)

// ─────────────────────────────────────────
// 값별 해석 (다) — 값에 따라 문구 생성
// ─────────────────────────────────────────

func interpretGlobal(score float64, topCVE string) string {
	level := "낮은 위험"
	switch {
	case score >= 80:
		level = "매우 높은 위험"
	case score >= 50:
		level = "높은 위험"
	case score >= 20:
		level = "중간 위험"
	}
	if topCVE != "" {
		return fmt.Sprintf("%.2f점으로 %s입니다. 주요 원인은 %s입니다.", score, level, topCVE)
	}
	return fmt.Sprintf("%.2f점으로 %s입니다.", score, level)
}

func interpretCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return fmt.Sprintf("%.1f점으로 최고 위험 등급입니다. 인증 없이 원격 코드 실행이 가능한 수준일 수 있습니다.", score)
	case score >= 7.0:
		return fmt.Sprintf("%.1f점으로 높은 위험입니다. 우선적으로 패치가 필요합니다.", score)
	case score >= 4.0:
		return fmt.Sprintf("%.1f점으로 중간 위험입니다.", score)
	default:
		return fmt.Sprintf("%.1f점으로 낮은 위험입니다.", score)
	}
}

func interpretEPSS(score float64) string {
	pct := score * 100
	switch {
	case score >= 0.5:
		return fmt.Sprintf("%.1f%%로 매우 높습니다. 가까운 시일 내 악용될 가능성이 큽니다.", pct)
	case score >= 0.1:
		return fmt.Sprintf("%.1f%%로 주의가 필요한 수준입니다.", pct)
	default:
		return fmt.Sprintf("%.1f%%로 낮은 편입니다.", pct)
	}
}

func interpretKEV(inKEV bool) string {
	if inKEV {
		return "KEV에 등재되어 있어 이미 실제 공격에 사용되고 있습니다. 즉시 조치를 권장합니다."
	}
	return "KEV 등재 이력이 없어 실제 악용 보고는 확인되지 않았습니다."
}

func interpretSSVC(ssvc string) string {
	switch ssvc {
	case "active":
		return "현재 활발히 악용되고 있는 단계입니다."
	case "poc":
		return "악용 개념증명(PoC)이 공개되어 있어 악용 가능성이 있습니다."
	default:
		return "공개된 악용 정황은 확인되지 않았습니다."
	}
}

func interpretLocal(score float64, exposed bool, attackLevel string) string {
	level := "낮은 편"
	switch {
	case score >= 80:
		level = "매우 높음"
	case score >= 50:
		level = "높음"
	case score >= 20:
		level = "중간"
	}
	exp := "외부 노출은 없고"
	if exposed {
		exp = "외부에 노출되어 있고"
	}
	return fmt.Sprintf("%.0f점으로 %s입니다. %s 공격 경로 위험은 %s 수준입니다.", score, level, exp, attackLevel)
}

func interpretExposure(exposed bool) string {
	if exposed {
		return "클러스터 외부에서 직접 접근 가능하여 공격 표면에 노출되어 있습니다."
	}
	return "외부에서 직접 접근할 수 없어 직접 공격받을 위험은 낮습니다."
}

func interpretAttackPath(level string, raw int) string {
	switch level {
	case "Critical", "emergency", "긴급":
		return fmt.Sprintf("%d점(Critical)으로, 침해 시 클러스터 전체를 장악당할 수 있는 매우 위험한 경로가 존재합니다.", raw)
	case "High", "warning", "경고":
		return fmt.Sprintf("%d점(High)으로, 권한 상승이나 횡적 이동 위험이 높습니다.", raw)
	case "Medium", "caution", "주의":
		return fmt.Sprintf("%d점(Medium)으로, 일부 확산 가능성이 있습니다.", raw)
	default:
		return fmt.Sprintf("%d점(Low)으로, 침해되더라도 확산 위험은 낮습니다.", raw)
	}
}

func interpretToxic(multiplier float64, rules []string) string {
	if multiplier > 1.0 && len(rules) > 0 {
		return fmt.Sprintf("위험 조합이 감지되어 ×%.2f 가중되었습니다. 적용 규칙: %s", multiplier, joinRules(rules))
	}
	if multiplier > 1.0 {
		return fmt.Sprintf("위험 조합이 감지되어 ×%.2f 가중되었습니다.", multiplier)
	}
	return "겹치는 위험 조합이 없어 가중되지 않았습니다 (×1.0)."
}

func joinRules(rules []string) string {
	out := ""
	for i, r := range rules {
		if i > 0 {
			out += ", "
		}
		out += r
	}
	return out
}

// risk_level → 한국어 라벨
func riskLabelKR(level string) string {
	switch level {
	case "emergency":
		return "긴급"
	case "warning":
		return "경고"
	case "caution":
		return "주의"
	case "safe":
		return "안전"
	default:
		return level
	}
}
