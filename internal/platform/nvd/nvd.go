package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		http:   &http.Client{Timeout: 10 * time.Second},
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
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type CVEInfo struct {
	CVEID        string
	Description  string
	CVSSScore    float64
	Severity     string
	VectorString string
	Found        bool
}

func (c *Client) FetchCVE(ctx context.Context, cveID string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd status %d", resp.StatusCode)
	}

	var data response
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}

	info := &CVEInfo{CVEID: cveID, Found: false}
	if len(data.Vulnerabilities) == 0 {
		return info, nil
	}

	v := data.Vulnerabilities[0].CVE
	info.Found = true

	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			info.Description = d.Value
			break
		}
	}

	if len(v.Metrics.CVSSMetricV31) > 0 {
		m := v.Metrics.CVSSMetricV31[0].CVSSData
		info.CVSSScore = m.BaseScore
		info.Severity = m.BaseSeverity
		info.VectorString = m.VectorString
	} else if len(v.Metrics.CVSSMetricV30) > 0 {
		m := v.Metrics.CVSSMetricV30[0].CVSSData
		info.CVSSScore = m.BaseScore
		info.Severity = m.BaseSeverity
		info.VectorString = m.VectorString
	}

	return info, nil
}
