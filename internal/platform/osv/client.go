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
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Severity         []OSVSeverity   `json:"severity"`
	Published        string          `json:"published"`
	Modified         string          `json:"modified"`
	Withdrawn        string          `json:"withdrawn,omitempty"` // 있으면 철회된 권고 (무효)
	Affected         []OSVAffected   `json:"affected,omitempty"`  // 영향 패키지 + 패치 버전 범위
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"` // GHSA/OSV가 종종 severity 라벨 제공
}

// OSVAffected는 한 취약점이 영향을 주는 패키지 + 버전 범위입니다.
type OSVAffected struct {
	Package OSVAffectedPackage `json:"package"`
	Ranges  []OSVRange         `json:"ranges,omitempty"`
}

// OSVAffectedPackage는 영향 패키지 식별 정보입니다.
type OSVAffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// OSVRange는 introduced/fixed/last_affected 이벤트로 표현되는 버전 범위입니다.
//
//	Type: "SEMVER" | "ECOSYSTEM" | "GIT"
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent는 버전 범위의 경계 이벤트입니다 (한 필드만 채워짐).
type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
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
// Order:
//   1. Direct numeric score (e.g., "7.5")
//   2. CVSS vector parsing (simple estimation)
//
// Returns 0.0 if no score found.
// ExtractFixedVersion은 취약점이 고쳐진 버전(fixed)을 추출합니다.
//
// 우리가 조회한 패키지(pkgName, 예: "org.springframework:spring-beans")에 매칭되는
// affected 항목을 우선하고, 그 ranges.events 중 마지막 fixed 값을 반환합니다.
//   - 매칭되는 항목이 없으면 전체 affected에서 첫 fixed로 폴백.
//   - fixed가 전혀 없으면(아직 패치 없음 / last_affected만 / GIT 커밋 범위) "" 반환.
//
// 반환값은 버전 문자열이며, 릴리스 "날짜"는 OSV가 주지 않음(3단계 deps.dev 필요).
func ExtractFixedVersion(v OSVVulnerability, pkgName string) string {
	pkgName = strings.TrimSpace(pkgName)

	lastFixedOf := func(a OSVAffected) string {
		fixed := ""
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue // 커밋 해시는 버전 의미 없음
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = e.Fixed // 마지막 fixed 우선 (보통 최신)
				}
			}
		}
		return fixed
	}

	// 1) 패키지명 매칭 우선
	if pkgName != "" {
		for _, a := range v.Affected {
			if strings.EqualFold(a.Package.Name, pkgName) ||
				(a.Package.PURL != "" && strings.Contains(a.Package.PURL, pkgName)) {
				if f := lastFixedOf(a); f != "" {
					return f
				}
			}
		}
	}

	// 2) 폴백: 전체 affected에서 첫 fixed
	for _, a := range v.Affected {
		if f := lastFixedOf(a); f != "" {
			return f
		}
	}
	return ""
}

func ExtractCVSSScore(v OSVVulnerability) (score float64, vector string) {
	bestScore := 0.0
	bestVector := ""

	for _, s := range v.Severity {
		// 1) Direct numeric (e.g., "7.5")
		if val, err := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); err == nil {
			if val > bestScore {
				bestScore = val
				bestVector = s.Score
			}
			continue
		}

		// 2) CVSS vector estimation
		if estimated := EstimateCVSSFromVector(s.Score); estimated > bestScore {
			bestScore = estimated
			bestVector = s.Score
		} else if bestVector == "" {
			bestVector = s.Score
		}
	}

	return bestScore, bestVector
}

// EstimateCVSSFromVector estimates a CVSS base score from a vector string.
//
// 정확한 CVSS 알고리즘은 아니지만, base metrics (AV/AC/PR/UI/C/I/A/S)에서
// 영향도와 공격성을 단순 매핑하여 대략의 base score를 추정합니다.
//
// CVSS:3.x 만 지원. v2/v4는 0 반환.
func EstimateCVSSFromVector(vector string) float64 {
	if vector == "" {
		return 0
	}
	upper := strings.ToUpper(vector)
	if !strings.Contains(upper, "CVSS:3") {
		return 0
	}

	hasMetric := func(metric string) bool {
		return strings.Contains(upper, "/"+metric)
	}

	// Impact metrics
	cImpact := 0.0
	if hasMetric("C:H") {
		cImpact = 0.56
	} else if hasMetric("C:L") {
		cImpact = 0.22
	}

	iImpact := 0.0
	if hasMetric("I:H") {
		iImpact = 0.56
	} else if hasMetric("I:L") {
		iImpact = 0.22
	}

	aImpact := 0.0
	if hasMetric("A:H") {
		aImpact = 0.56
	} else if hasMetric("A:L") {
		aImpact = 0.22
	}

	// ISC = 1 - (1-C)(1-I)(1-A)
	isc := 1 - (1-cImpact)*(1-iImpact)*(1-aImpact)
	if isc <= 0 {
		return 0
	}

	scopeChanged := hasMetric("S:C")

	impact := 6.42 * isc
	if scopeChanged {
		impact = 7.52*(isc-0.029) - 3.25*pow(isc-0.02, 15)
	}

	// Exploitability
	av := 0.85
	if hasMetric("AV:A") {
		av = 0.62
	} else if hasMetric("AV:L") {
		av = 0.55
	} else if hasMetric("AV:P") {
		av = 0.2
	}

	ac := 0.77
	if hasMetric("AC:H") {
		ac = 0.44
	}

	pr := 0.85
	if scopeChanged {
		if hasMetric("PR:L") {
			pr = 0.68
		} else if hasMetric("PR:H") {
			pr = 0.5
		}
	} else {
		if hasMetric("PR:L") {
			pr = 0.62
		} else if hasMetric("PR:H") {
			pr = 0.27
		}
	}

	ui := 0.85
	if hasMetric("UI:R") {
		ui = 0.62
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scopeChanged {
		base = min10(1.08 * (impact + exploitability))
	} else {
		base = min10(impact + exploitability)
	}

	if base <= 0 {
		return 0
	}

	// Round up to nearest 0.1
	return roundUp01(base)
}

// ExtractDBSpecificSeverity는 database_specific.severity 라벨을 추출합니다.
//
// GHSA는 종종 다음 형식으로 제공:
//   { "severity": "CRITICAL" }
func ExtractDBSpecificSeverity(v OSVVulnerability) string {
	if len(v.DatabaseSpecific) == 0 {
		return ""
	}
	var dbs struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(v.DatabaseSpecific, &dbs); err != nil {
		return ""
	}
	return strings.Title(strings.ToLower(strings.TrimSpace(dbs.Severity)))
}

// ─────────────────────────────────────────
// math helpers (라이브러리 추가 없이 진행)
// ─────────────────────────────────────────

func pow(x float64, n int) float64 {
	result := 1.0
	for i := 0; i < n; i++ {
		result *= x
	}
	return result
}

func min10(v float64) float64 {
	if v > 10 {
		return 10
	}
	if v < 0 {
		return 0
	}
	return v
}

func roundUp01(v float64) float64 {
	rounded := float64(int(v*10+0.999)) / 10
	if rounded > 10 {
		return 10
	}
	return rounded
}
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
