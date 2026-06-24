// GRC 보조: 텍스트를 벡터로 변환하여 GRC 증적 평가(grc_embedding_eval)의
// 코사인 유사도 계산에 사용한다.
//
// Provider 선택 (NewClient):
//   - VOYAGE_API_KEY 환경변수가 있으면 → Voyage AI Embeddings API 사용
//     (모델: VOYAGE_MODEL, 기본 voyage-3.5 / 출력 1024차원 — pgvector vector(1024)와 일치)
//   - 없으면 → 로컬 BGE-M3 FastAPI 서버(url) 사용 (기존 동작)
//
// ⚠ provider를 바꾸면 벡터 공간이 달라진다. 이미 저장된 임베딩(문서/문장)은 이전
// provider 공간이므로, 전환 후에는 저장된 임베딩을 모두 재계산(재업로드)해야 검색이
// 정상 동작한다. 차원은 양쪽 모두 1024로 맞춘다.
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
	"os"
	"time"
)

const (
	defaultTimeout    = 30 * time.Minute // BGE-M3 on CPU with large texts can take 10+ minutes
	maxRetries        = 3
	initialRetryDelay = 2 * time.Second

	// Voyage 설정 — 출력 차원은 pgvector 컬럼(vector(1024))과 반드시 일치해야 한다.
	voyageURL      = "https://api.voyageai.com/v1/embeddings"
	voyageDim      = 1024
	voyageMaxBatch = 128 // 요청당 텍스트 수 상한(토큰 한도 여유 확보)
)

// Client calls either Voyage AI (apiKey 설정 시) or a local BGE-M3 FastAPI server.
type Client struct {
	url        string // BGE-M3 서버 URL (폴백용)
	apiKey     string // Voyage API key — 있으면 Voyage provider 사용
	model      string // Voyage 모델명
	httpClient *http.Client
}

// NewClient creates a new embedding client.
// VOYAGE_API_KEY가 있으면 Voyage를, 없고 url이 있으면 BGE-M3를 사용한다.
// 둘 다 없으면 Available()=false → 모든 메서드 nil 반환(임베딩 비활성).
func NewClient(url string) *Client {
	c := &Client{
		url:        url,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	if key := os.Getenv("VOYAGE_API_KEY"); key != "" {
		c.apiKey = key
		c.model = os.Getenv("VOYAGE_MODEL")
		if c.model == "" {
			c.model = "voyage-3.5"
		}
		log.Printf("[embedding] provider=voyage model=%s dim=%d", c.model, voyageDim)
	} else if url != "" {
		log.Printf("[embedding] provider=bge-m3 url=%s", url)
	}
	return c
}

// Available returns true if a provider (Voyage or BGE-M3) is configured.
func (c *Client) Available() bool {
	return c != nil && (c.apiKey != "" || c.url != "")
}

// UsingVoyage reports whether the Voyage provider is active.
func (c *Client) UsingVoyage() bool { return c != nil && c.apiKey != "" }

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

// EmbedBatch generates embedding vectors for multiple texts, preserving order.
// Empty strings yield nil at their position. Returns nil if unavailable/empty.
func (c *Client) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if !c.Available() || len(texts) == 0 {
		return nil, nil
	}

	// Filter out empty strings, remembering original positions.
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

	filteredEmb, err := c.embedFiltered(ctx, filtered)
	if err != nil {
		return nil, err
	}
	if len(filteredEmb) != len(filtered) {
		log.Printf("[embedding] expected %d embeddings, got %d", len(filtered), len(filteredEmb))
		return nil, nil
	}

	// Map back to original indices.
	out := make([][]float32, len(texts))
	for fi, oi := range idxMap {
		out[oi] = filteredEmb[fi]
	}
	return out, nil
}

// embedFiltered dispatches to the active provider for a non-empty, no-empties slice.
func (c *Client) embedFiltered(ctx context.Context, texts []string) ([][]float32, error) {
	if c.UsingVoyage() {
		return c.embedVoyage(ctx, texts)
	}
	return c.embedBGE(ctx, texts)
}

// ── Voyage provider ──

type voyageRequest struct {
	Input           []string `json:"input"`
	Model           string   `json:"model"`
	OutputDimension int      `json:"output_dimension,omitempty"`
}

type voyageResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
}

// embedVoyage calls the Voyage Embeddings API, chunking to voyageMaxBatch per request.
// Returns embeddings aligned to the input order. Errors are returned (loud) so a
// paid-API failure isn't silently masked.
func (c *Client) embedVoyage(ctx context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for start := 0; start < len(texts); start += voyageMaxBatch {
		end := start + voyageMaxBatch
		if end > len(texts) {
			end = len(texts)
		}
		chunk := texts[start:end]
		chunkEmb, err := c.embedVoyageChunk(ctx, chunk)
		if err != nil {
			return nil, fmt.Errorf("voyage chunk [%d:%d]: %w", start, end, err)
		}
		copy(out[start:end], chunkEmb)
	}
	return out, nil
}

func (c *Client) embedVoyageChunk(ctx context.Context, chunk []string) ([][]float32, error) {
	body, err := json.Marshal(voyageRequest{
		Input:           chunk,
		Model:           c.model,
		OutputDimension: voyageDim,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(float64(initialRetryDelay) * math.Pow(2, float64(attempt-1)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, voyageURL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("request create: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[embedding] voyage attempt %d: %v", attempt+1, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("voyage status %d: %s", resp.StatusCode, string(respBody))
			log.Printf("[embedding] %v", lastErr)
			// 4xx(키/요청 오류)는 재시도해도 동일 — 즉시 중단.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return nil, lastErr
			}
			continue
		}

		var vr voyageResponse
		decErr := json.NewDecoder(resp.Body).Decode(&vr)
		resp.Body.Close()
		if decErr != nil {
			return nil, fmt.Errorf("decode: %w", decErr)
		}
		if len(vr.Data) != len(chunk) {
			return nil, fmt.Errorf("expected %d embeddings, got %d", len(chunk), len(vr.Data))
		}
		// data[].index 순서 보장이 없으므로 index로 정렬 배치.
		emb := make([][]float32, len(chunk))
		for _, d := range vr.Data {
			if d.Index < 0 || d.Index >= len(chunk) {
				return nil, fmt.Errorf("voyage index out of range: %d", d.Index)
			}
			emb[d.Index] = d.Embedding
		}
		return emb, nil
	}
	return nil, lastErr
}

// ── BGE-M3 provider (로컬 FastAPI) ──

type embedRequest struct {
	Texts []string `json:"texts"`
}

type embedResponse struct {
	Embeddings [][]float32 `json:"embeddings"`
}

// embedBGE calls the local BGE-M3 server. On exhausted retries it returns (nil,nil)
// for graceful degradation (기존 동작 보존).
func (c *Client) embedBGE(ctx context.Context, texts []string) ([][]float32, error) {
	body, err := json.Marshal(embedRequest{Texts: texts})
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

		if len(result.Embeddings) != len(texts) {
			log.Printf("[embedding] expected %d embeddings, got %d", len(texts), len(result.Embeddings))
			return nil, nil
		}
		lastErr = nil
		break
	}

	if lastErr != nil {
		log.Printf("[embedding] all %d attempts failed: %v", maxRetries, lastErr)
		return nil, nil // graceful degradation
	}
	return result.Embeddings, nil
}
