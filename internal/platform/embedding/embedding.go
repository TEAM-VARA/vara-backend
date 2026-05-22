package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
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
			Timeout: 30 * time.Second,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embedding request create: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[embedding] server unreachable (%s): %v", c.url, err)
		return nil, nil // graceful degradation
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[embedding] server returned %d: %s", resp.StatusCode, string(respBody))
		return nil, nil // graceful degradation
	}

	var result embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("embedding response decode: %w", err)
	}

	if len(result.Embeddings) != len(filtered) {
		log.Printf("[embedding] expected %d embeddings, got %d", len(filtered), len(result.Embeddings))
		return nil, nil
	}

	// Map back to original indices.
	out := make([][]float32, len(texts))
	for fi, oi := range idxMap {
		out[oi] = result.Embeddings[fi]
	}

	return out, nil
}
