// GRC 보조: Colab 호스팅 Qwen 2.5 FastAPI 서버와 통신하여 ISMS-P 지침 함의 판정을 수행.
// embedding.Client와 동일한 패턴: retry, timeout, graceful degradation.
package vlm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"time"
)

const (
	defaultTimeout    = 120 * time.Second // LLM inference: 보통 10-40s, 넉넉히 120s
	maxRetries        = 2
	initialRetryDelay = 3 * time.Second
)

// Client calls a Colab-hosted Qwen 2.5 FastAPI judge server.
type Client struct {
	url        string // base URL, e.g. https://xxxx.ngrok-free.app
	httpClient *http.Client
}

// NewClient creates a new VLM judge client.
// If url is empty, all methods return nil results (VLM disabled).
func NewClient(url string) *Client {
	return &Client{
		url: url,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Available returns true if the VLM server URL is configured.
func (c *Client) Available() bool {
	return c != nil && c.url != ""
}

// ── Request / Response ──

// RetrievedSentence is a guideline sentence found by BGE-M3 cosine retrieval.
type RetrievedSentence struct {
	Index int     `json:"index"`
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

// JudgeRequest is sent to POST {url}/v1/judge.
type JudgeRequest struct {
	RuleRequirement    string              `json:"rule_requirement"`
	Polarity           string              `json:"polarity"`
	Parameters         map[string]string   `json:"parameters"`
	RetrievedSentences []RetrievedSentence `json:"retrieved_sentences"`
}

// JudgeResponse is returned by the Colab server.
type JudgeResponse struct {
	Verdict     string `json:"verdict"`  // 충족|부분|불충족|판정불가
	BasisIdx    []int  `json:"근거문장"`
	MissingElem string `json:"누락요소"`
	Modality    string `json:"양태"` // 의무|권고|없음
}

// Judge sends a judgment request to the VLM server and returns the verdict.
// Returns nil, nil if the client is unavailable or all retries fail (graceful degradation).
func (c *Client) Judge(ctx context.Context, req JudgeRequest) (*JudgeResponse, error) {
	if !c.Available() {
		return nil, nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vlm request marshal: %w", err)
	}

	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(float64(initialRetryDelay) * math.Pow(2, float64(attempt-1)))
			log.Printf("[vlm] retry %d/%d after %v", attempt+1, maxRetries, delay)
			select {
			case <-ctx.Done():
				return nil, nil
			case <-time.After(delay):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/judge", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("vlm request create: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("ngrok-skip-browser-warning", "true")

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			log.Printf("[vlm] attempt %d: server unreachable (%s): %v", attempt+1, c.url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
			log.Printf("[vlm] attempt %d: server returned %d: %s", attempt+1, resp.StatusCode, string(respBody))
			continue
		}

		var result JudgeResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("vlm response decode: %w", err)
		}
		resp.Body.Close()

		// Validate verdict value.
		switch result.Verdict {
		case "충족", "부분", "불충족", "판정불가":
			// OK
		default:
			result.Verdict = "판정불가"
		}

		return &result, nil
	}

	// All retries failed — graceful degradation.
	log.Printf("[vlm] all %d attempts failed: %v", maxRetries, lastErr)
	return nil, nil
}
