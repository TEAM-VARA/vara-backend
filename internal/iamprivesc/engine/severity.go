package engine

// 위험도 등급 — Python SEVERITY_RANK/ICON/LABEL 대응.
var (
	SeverityRank  = map[string]int{"critical": 3, "warning": 2, "info": 1, "ok": 0}
	SeverityIcon  = map[string]string{"critical": "❌", "warning": "🟡", "info": "ℹ️", "ok": "✅"}
	SeverityLabel = map[string]string{"critical": "치명적", "warning": "주의", "info": "참고", "ok": "양호"}
)

var severityOrder = []string{"critical", "warning", "info", "ok"}

// downgrade 는 위험도를 한 단계 낮춘다(최하 ok 에서 멈춤).
func downgrade(sev string) string {
	for i, v := range severityOrder {
		if v == sev {
			if i+1 < len(severityOrder) {
				return severityOrder[i+1]
			}
			return sev
		}
	}
	return sev
}
