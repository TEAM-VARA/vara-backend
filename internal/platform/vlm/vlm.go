// GRC 보조: Ollama(Qwen 2.5) 서버와 통신하여 ISMS-P 지침 함의 판정을 수행.
// Colab FastAPI 프롬프트 로직을 Go에 내장하여 외부 터널(ngrok/cloudflare) 없이 동작.
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
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout    = 300 * time.Second // CPU 추론: 최대 5분
	maxRetries        = 2
	initialRetryDelay = 3 * time.Second

	systemPrompt = `ISMS-P 지침 충족 판정기. 검색된 문장에 요건 관련 내용이 있는지만 판단한다.

규칙:
- 검색된 문장 중 요건과 관련된 내용이 하나라도 있으면 → "충족"
- 동의어·유사 표현은 같은 의미다 (예: "공용 금지"="공동사용 금지", "회수"="반납")
- 관련 내용이 전혀 없을 때만 → "불충족"
- 애매하면 "충족"으로 판정한다

반드시 아래 JSON만 출력:
{"verdict":"충족 또는 불충족","근거문장":[번호],"누락요소":""}`
)

var jsonRe = regexp.MustCompile(`\{[^{}]*\}`)

// Client calls an Ollama server for LLM inference.
type Client struct {
	url        string // Ollama base URL, e.g. http://ollama:11434
	model      string // model tag, e.g. qwen2.5:3b
	httpClient *http.Client
}

// NewClient creates a new VLM judge client.
// If url is empty, all methods return nil results (VLM disabled).
func NewClient(url, model string) *Client {
	if model == "" {
		model = "qwen2.5:7b"
	}
	return &Client{
		url:   url,
		model: model,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// Available returns true if the VLM server URL is configured.
func (c *Client) Available() bool {
	return c != nil && c.url != ""
}

// ── Request / Response (external — unchanged) ──

// RetrievedSentence is a guideline sentence found by BGE-M3 cosine retrieval.
type RetrievedSentence struct {
	Index int     `json:"index"`
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

// JudgeRequest is the input from the GRC service.
type JudgeRequest struct {
	RuleRequirement    string              `json:"rule_requirement"`
	Polarity           string              `json:"polarity"`
	Parameters         map[string]string   `json:"parameters"`
	RetrievedSentences []RetrievedSentence `json:"retrieved_sentences"`
}

// JudgeResponse is returned to the GRC service.
type JudgeResponse struct {
	Verdict     string          `json:"verdict"` // 충족|부분|불충족|판정불가
	RawBasis    json.RawMessage `json:"근거문장"`
	BasisIdx    []int           `json:"-"`
	MissingElem string          `json:"누락요소"`
	Modality    string          `json:"양태"` // 의무|권고|없음
}

// parseBasisIdx converts RawBasis (may be []int, string, or single int) into BasisIdx.
func (r *JudgeResponse) parseBasisIdx() {
	if len(r.RawBasis) == 0 {
		return
	}
	// Try []int first
	var arr []int
	if err := json.Unmarshal(r.RawBasis, &arr); err == nil {
		r.BasisIdx = arr
		return
	}
	// Try single int
	var single int
	if err := json.Unmarshal(r.RawBasis, &single); err == nil {
		r.BasisIdx = []int{single}
		return
	}
	// Try string like "1" or "1,2"
	var s string
	if err := json.Unmarshal(r.RawBasis, &s); err == nil {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if v, err := strconv.Atoi(part); err == nil {
				r.BasisIdx = append(r.BasisIdx, v)
			}
		}
	}
}

// ── Ollama API types ──

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  ollamaOptions   `json:"options"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
}

type ollamaChatResponse struct {
	Message ollamaMessage `json:"message"`
}

// buildUserPrompt replicates the Colab colab_server.py prompt template.
func buildUserPrompt(req JudgeRequest) string {
	var b strings.Builder

	b.WriteString("## 룰 요건\n")
	b.WriteString(req.RuleRequirement)
	b.WriteString("\n\n## 극성\n")
	b.WriteString(req.Polarity)

	b.WriteString("\n\n## 파라미터\n")
	if len(req.Parameters) > 0 {
		paramJSON, _ := json.Marshal(req.Parameters)
		b.Write(paramJSON)
	} else {
		b.WriteString("없음")
	}

	b.WriteString("\n\n## 검색된 지침서 문장\n")
	for _, s := range req.RetrievedSentences {
		fmt.Fprintf(&b, "[%d] %s (유사도: %.3f)\n", s.Index, s.Text, s.Score)
	}

	b.WriteString("\n위 문장들이 룰 요건을 함의(충족)하는지 판정하라. JSON만 출력.")
	return b.String()
}

// Judge sends a judgment request to the Ollama server and returns the verdict.
// Returns nil, nil if the client is unavailable or all retries fail (graceful degradation).
func (c *Client) Judge(ctx context.Context, req JudgeRequest) (*JudgeResponse, error) {
	if !c.Available() {
		return nil, nil
	}

	chatReq := ollamaChatRequest{
		Model: c.model,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserPrompt(req)},
		},
		Stream:  false,
		Options: ollamaOptions{Temperature: 0.0},
	}

	body, err := json.Marshal(chatReq)
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

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/api/chat", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("vlm request create: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

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

		var chatResp ollamaChatResponse
		if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("vlm response decode: %w", err)
		}
		resp.Body.Close()

		// Parse JSON from LLM raw text (same logic as colab_server.py).
		raw := strings.TrimSpace(chatResp.Message.Content)
		log.Printf("[vlm] raw response: %s", raw)

		result := parseJudgeJSON(raw)
		return &result, nil
	}

	// All retries failed — graceful degradation.
	log.Printf("[vlm] all %d attempts failed: %v", maxRetries, lastErr)
	return nil, nil
}

// parseJudgeJSON extracts the first JSON object from LLM output and maps it to JudgeResponse.
func parseJudgeJSON(raw string) JudgeResponse {
	fallback := JudgeResponse{
		Verdict:     "판정불가",
		RawBasis:    json.RawMessage(`[]`),
		MissingElem: "",
		Modality:    "없음",
	}

	match := jsonRe.FindString(raw)
	if match == "" {
		return fallback
	}

	var result JudgeResponse
	if err := json.Unmarshal([]byte(match), &result); err != nil {
		return fallback
	}

	// Validate verdict value.
	switch result.Verdict {
	case "충족", "부분", "불충족", "판정불가":
		// OK
	default:
		result.Verdict = "판정불가"
	}

	result.parseBasisIdx()
	return result
}
