package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client : NVD CVE API 클라이언트
//
// API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
// API Key 없으면 5초당 5회 제한, Key 있으면 50회.
type Client struct {
	apiKey string
	http   *http.Client
}

func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 30 * time.Second}, // NVD는 느림(20~30s 흔함) → 10s는 너무 짧아 타임아웃 빈발
	}
}

type response struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"` // 예: "CWE-502"
				} `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL    string   `json:"url"`
				Tags   []string `json:"tags"` // 예: "Vendor Advisory", "Patch", "Exploit"
				Source string   `json:"source"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Reference — NVD가 제공하는 외부 참조 링크 (advisory enrichment fetch 후보).
type Reference struct {
	URL  string
	Tags []string
}

type CVEInfo struct {
	CVEID        string
	Description  string
	CVSSScore    float64
	Severity     string
	VectorString string
	CWEs         []string    // weaknesses 에서 추출한 CWE-ID 목록 (예: ["CWE-502"])
	References   []Reference // 권고문/패치 링크 — enrichment advisory fetch 대상
	Found        bool
}

// nvdMaxAttempts: NVD가 503/타임아웃을 자주 뱉으므로 일시적 오류는 백오프 후 재시도한다.
const nvdMaxAttempts = 3

func (c *Client) FetchCVE(ctx context.Context, cveID string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	var lastErr error
	for attempt := 1; attempt <= nvdMaxAttempts; attempt++ {
		info, retryable, err := c.fetchOnce(ctx, url, cveID)
		if err == nil {
			return info, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
		// 일시적 오류(503/429/타임아웃) → 백오프(3s, 6s) 후 재시도. ctx 취소는 존중.
		if attempt < nvdMaxAttempts {
			select {
			case <-time.After(time.Duration(attempt*3) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return nil, lastErr
}

// fetchOnce는 NVD를 1회 호출한다. retryable=true면 일시적 오류(재시도 권장).
func (c *Client) fetchOnce(ctx context.Context, url, cveID string) (info *CVEInfo, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, false, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// 네트워크 오류/타임아웃 → 재시도 가능
		return nil, true, fmt.Errorf("nvd fetch: %w", err)
	}
	defer resp.Body.Close()

	// 503(과부하)·429(rate limit)는 일시적 → 재시도
	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
		return nil, true, fmt.Errorf("nvd status %d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, false, fmt.Errorf("nvd status %d", resp.StatusCode)
	}

	var data response
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, false, fmt.Errorf("nvd decode: %w", err)
	}

	out := &CVEInfo{CVEID: cveID, Found: false}
	if len(data.Vulnerabilities) == 0 {
		return out, false, nil
	}

	v := data.Vulnerabilities[0].CVE
	out.Found = true

	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			out.Description = d.Value
			break
		}
	}

	if len(v.Metrics.CVSSMetricV31) > 0 {
		m := v.Metrics.CVSSMetricV31[0].CVSSData
		out.CVSSScore = m.BaseScore
		out.Severity = m.BaseSeverity
		out.VectorString = m.VectorString
	} else if len(v.Metrics.CVSSMetricV30) > 0 {
		m := v.Metrics.CVSSMetricV30[0].CVSSData
		out.CVSSScore = m.BaseScore
		out.Severity = m.BaseSeverity
		out.VectorString = m.VectorString
	}

	// CWE (weaknesses): CWE-* 형태의 영문 값만 수집(중복 제거).
	seenCWE := map[string]bool{}
	for _, w := range v.Weaknesses {
		for _, d := range w.Description {
			val := strings.TrimSpace(d.Value)
			if strings.HasPrefix(val, "CWE-") && !seenCWE[val] {
				seenCWE[val] = true
				out.CWEs = append(out.CWEs, val)
			}
		}
	}

	// References: advisory enrichment fetch 후보. 태그까지 보존(우선순위 판단용).
	for _, r := range v.References {
		if r.URL != "" {
			out.References = append(out.References, Reference{URL: r.URL, Tags: r.Tags})
		}
	}

	return out, false, nil
}
