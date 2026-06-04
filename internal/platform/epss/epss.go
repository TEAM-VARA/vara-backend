package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client : FIRST.org EPSS API 클라이언트
type Client struct {
	http *http.Client
}

func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

type response struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

type Info struct {
	CVEID      string
	Score      float64
	Percentile float64
	Found      bool
}

func (c *Client) FetchEPSS(ctx context.Context, cveID string) (*Info, error) {
	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("epss status %d", resp.StatusCode)
	}

	var data response
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("epss decode: %w", err)
	}

	info := &Info{CVEID: cveID, Found: false}
	if len(data.Data) == 0 {
		return info, nil
	}

	d := data.Data[0]
	info.Found = true
	fmt.Sscanf(d.EPSS, "%f", &info.Score)
	fmt.Sscanf(d.Percentile, "%f", &info.Percentile)
	return info, nil
}
