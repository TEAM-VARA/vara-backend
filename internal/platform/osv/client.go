package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// osv.dev API 클라이언트
//
// API 문서: https://google.github.io/osv.dev/api/
// 기본 엔드포인트: https://api.osv.dev/v1/query
//
// 사용법:
//   client := osv.NewClient()
//   vulns, err := client.QueryByPURL(ctx, "pkg:deb/debian/openssl@1.1.0f")
//
// Rate limit: 무료, 너그러움 (분당 수백건). 다만 너무 빠르면 429 가능.

const (
	defaultBaseURL     = "https://api.osv.dev/v1/query"
	defaultTimeout     = 30 * time.Second
	defaultUserAgent   = "VARA-Scanner/1.0"
)

// Client는 osv.dev API 호출 클라이언트입니다.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient는 기본 설정으로 Client를 생성합니다.
func NewClient() *Client {
	return &Client{
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// ─────────────────────────────────────────
// API 요청/응답 타입
// ─────────────────────────────────────────

// queryRequest: POST body
type queryRequest struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	PURL string `json:"purl"`
}

// queryResponse: API 응답
type queryResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability는 osv.dev가 반환하는 단일 취약점입니다.
//
// 실제 응답은 더 많은 필드가 있지만, 우리가 쓰는 것만 정의.
type OSVVulnerability struct {
	ID        string         `json:"id"`        // 'CVE-2017-3735' / 'GHSA-...' / 'GO-2024-...'
	Aliases   []string       `json:"aliases"`   // 별칭 ID들
	Summary   string         `json:"summary"`
	Details   string         `json:"details"`
	Severity  []OSVSeverity  `json:"severity"`
	Published string         `json:"published"`
	Modified  string         `json:"modified"`
}

// OSVSeverity는 한 취약점의 한 severity 표기입니다.
//
// 타입 예시:
//   "CVSS_V2": "AV:N/AC:L/Au:N/C:N/I:N/A:P"
//   "CVSS_V3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C"
//   "CVSS_V4": "..."
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// ─────────────────────────────────────────
// 호출
// ─────────────────────────────────────────

// QueryByPURL은 PURL로 osv.dev를 조회하여 매칭되는 모든 취약점을 반환합니다.
//
// 결과가 없으면 (empty slice, nil) 반환.
// HTTP 오류 시 (nil, error).
func (c *Client) QueryByPURL(ctx context.Context, purl string) ([]OSVVulnerability, error) {
	if purl == "" {
		return nil, fmt.Errorf("purl is required")
	}

	body, err := json.Marshal(queryRequest{
		Package: osvPackage{PURL: purl},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (429), retry later")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv.dev returned %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed queryResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return parsed.Vulns, nil
}

// ─────────────────────────────────────────
// 헬퍼: CVSS 점수 추출
// ─────────────────────────────────────────

// ExtractCVSSScore extracts the highest CVSS base score from a vulnerability.
//
// osv.dev returns severity strings in CVSS vector format. We need to extract
// the numeric base score. For CVSS_V3 the score is the first number after
// "CVSS:3.x/". For CVSS_V4 similar.
//
// Returns 0.0 if no score found.
func ExtractCVSSScore(v OSVVulnerability) (score float64, vector string) {
	bestScore := 0.0
	bestVector := ""

	for _, s := range v.Severity {
		// Score in osv.dev is typically a CVSS vector string, but sometimes
		// it's already a numeric base score string like "7.5".
		// Try direct parse first (numeric), then vector parse.
		if val, err := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); err == nil {
			if val > bestScore {
				bestScore = val
				bestVector = s.Score
			}
			continue
		}

		// Vector format: try to compute base score from vector.
		// Without a full CVSS calculator we cannot derive it precisely,
		// so we look for a base score embedded in the vector if any
		// (some entries include "score=7.5" style metadata).
		// As fallback we keep the vector for traceability and 0 score.
		if bestVector == "" {
			bestVector = s.Score
		}
	}

	return bestScore, bestVector
}

// ClassifySeverity returns a label for a CVSS score.
//
//	>= 9.0  Critical
//	>= 7.0  High
//	>= 4.0  Medium
//	>  0.0  Low
//	== 0.0  None (or Unknown)
func ClassifySeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Unknown"
	}
}
