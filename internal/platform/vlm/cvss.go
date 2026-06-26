package vlm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// CVSSEstimate는 LLM이 CVE 설명으로 추정한 CVSS 결과입니다.
type CVSSEstimate struct {
	CVSS       float64 `json:"cvss"`       // 0~10
	Confidence float64 `json:"confidence"` // 0~1
	Reason     string  `json:"reason"`
}

const cvssSystemPrompt = `너는 취약점 심각도 추정기다. 주어진 CVE 설명을 읽고 CVSS v3.1 base score(0.0~10.0)를 추정한다.
규칙:
- 설명이 빈약하거나 불확실하면 confidence를 낮게(<=0.5) 준다.
- 권위 있는 점수가 아니므로 과대평가하지 말고 보수적으로 추정한다.
- 원격 코드 실행/인증 우회 등 명백히 심각하면 높게, 정보 노출/DoS 등은 중간 이하로.
반드시 아래 JSON만 출력(다른 텍스트 금지):
{"cvss": 0.0~10.0, "confidence": 0.0~1.0, "reason": "한 줄 근거"}`

// EstimateCVSS는 CVE 설명으로 CVSS를 추정합니다.
// Claude 미설정·설명 없음·호출 실패·파싱 실패 시 (nil, nil)로 graceful degradation.
func (c *Client) EstimateCVSS(ctx context.Context, cveID, description string) (*CVSSEstimate, error) {
	if !c.UsingClaude() || strings.TrimSpace(description) == "" {
		return nil, nil
	}

	user := fmt.Sprintf("## CVE\n%s\n\n## 설명\n%s\n\n위 취약점의 CVSS v3.1 base score를 추정해 JSON으로만 출력하라.", cveID, description)

	raw, err := c.doChat(ctx, cvssSystemPrompt, user, 0.0, defaultMaxTokens)
	if err != nil {
		return nil, nil
	}

	match := jsonRe.FindString(strings.TrimSpace(raw))
	if match == "" {
		return nil, nil
	}
	var est CVSSEstimate
	if err := json.Unmarshal([]byte(match), &est); err != nil {
		return nil, nil
	}

	// 범위 보정
	if est.CVSS < 0 {
		est.CVSS = 0
	} else if est.CVSS > 10 {
		est.CVSS = 10
	}
	if est.Confidence < 0 {
		est.Confidence = 0
	} else if est.Confidence > 1 {
		est.Confidence = 1
	}
	return &est, nil
}
