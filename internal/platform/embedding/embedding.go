// GRC 보조: BGE-M3 임베딩 서버(FastAPI)와 통신하여 텍스트를 벡터로 변환.
// GRC 증적 평가(grc_embedding_eval) 시 증적 텍스트와 룰 기준 텍스트 간
// 코사인 유사도를 계산하는 데 사용된다.
package embedding

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
	defaultTimeout    = 300 * time.Second // BGE-M3 on CPU can be slow
	maxRetries        = 3
	initialRetryDelay = 2 * time.Second
)

// Client calls a BGE-M3 FastAPI embedding server.
type Client struct {
	url        string
	httpClient *http.Client
}

// NewClient creates a new embedding client.
// If url is empty, all methods return nil (embeddings disabled).
func NewClient(url string) *Client {
	return &Client{
		url: url,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Available returns true if the embedding server URL is configured.
func (c *Client) Available() bool {
	return c != nil && c.url != ""
}

type embedRequest struct {
	Texts []string `json:"texts"`
}

type embedResponse struct {
	Embeddings [][]float32 `json:"embeddings"`
}

// Embed generates a single embedding vector for the given text.
// Returns nil (not error) if the client is unavailable or text is empty.
func (c *Client) Embed(ctx context.Context, text string) ([]float32, error) {
	if !c.Available() || text == "" {
		return nil, nil
	}

	results, err := c.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results[0], nil
}

// EmbedBatch generates embedding vectors for multiple texts.
// Returns nil (not error) if the client is unavailable or texts is empty.
func (c *Client) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if !c.Available() || len(texts) == 0 {
		return nil, nil
	}

	// Filter out empty strings.
	var filtered []string
	idxMap := make(map[int]int) // filtered index -> original index
	for i, t := range texts {
		if t != "" {
			idxMap[len(filtered)] = i
			filtered = append(filtered, t)
		}
	}
	if len(filtered) == 0 {
		return nil, nil
	}

	body, err := json.Marshal(embedRequest{Texts: filtered})
	if err != nil {
		return nil, fmt.Errorf("embedding request marshal: %w", err)
	}

	var result embedResponse
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(float64(initialRetryDelay) * math.Pow(2, float64(attempt-1)))
			log.Printf("[embedding] retry %d/%d after %v", attempt+1, maxRetries, delay)
			select {
			case <-ctx.Done():
				return nil, nil
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("embedding request create: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[embedding] attempt %d: server unreachable (%s): %v", attempt+1, c.url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
			log.Printf("[embedding] attempt %d: server returned %d: %s", attempt+1, resp.StatusCode, string(respBody))
			continue
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("embedding response decode: %w", err)
		}
		resp.Body.Close()

		if len(result.Embeddings) != len(filtered) {
			log.Printf("[embedding] expected %d embeddings, got %d", len(filtered), len(result.Embeddings))
			return nil, nil
		}

		lastErr = nil
		break
	}

	if lastErr != nil {
		log.Printf("[embedding] all %d attempts failed: %v", maxRetries, lastErr)
		return nil, nil // graceful degradation
	}

	// Map back to original indices.
	out := make([][]float32, len(texts))
	for fi, oi := range idxMap {
		out[oi] = result.Embeddings[fi]
	}

	return out, nil
}
