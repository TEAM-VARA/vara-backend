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
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout    = 300 * time.Second // CPU 추론: 최대 5분
	healthTimeout     = 2 * time.Second   // 도달성 핑: 짧게 (안 뜨면 즉시 비가동 판정)
	maxRetries        = 2
	initialRetryDelay = 3 * time.Second

	systemPrompt = `ISMS-P 지침 충족 판정기. 검색된 문장이 룰 요건을 실제로 규정하는지 판단한다.

판정 절차:
1단계 — 대상 확인 (가장 중요):
근거로 삼을 문장은 룰 요건이 규율하는 "대상"을 직접 다루어야 한다.
대상 = 요건의 객체 (예: 자산목록, 흐름도, 클라우드 설정, 특수계정, 비밀번호, 패치 등).
단어가 겹쳐도 대상이 다르면 무관한 문장이며 근거로 쓸 수 없다.
반례 (이런 문장은 근거가 아니다):
- "DBMS 변경 시 문서도 변경한다" → '자산목록 최신 유지' 요건의 근거 아님 (대상: DB 문서 ≠ 자산목록)
- "내부 DNS는 외부에서 접근할 수 없다" → '시스템의 외부 인터넷 접속 통제' 요건의 근거 아님 (방향: 외부→내부 차단 ≠ 내부→외부 통제)
- "정보보안 책임자를 지정할 수 있다" → '자산별 책임자 지정' 요건의 근거 아님 (대상: 조직 총괄 책임자 ≠ 개별 자산 책임자)
- "테스트 시 운영 데이터 노출을 방지한다" → '개발과 운영 환경 분리' 요건의 근거 아님 (대상: 데이터 보호 ≠ 환경 분리)

2단계 — 내용 판정:
- 대상이 일치하는 문장이 요건의 행위·기준을 규정하면 → "충족"
- 동의어·유사 표현은 같은 의미다 (예: "공용 금지"="공동사용 금지", "회수"="반납")
- 요건에 수치·주기가 있으면 문장의 수치·주기가 요건 이상이어야 한다 (예: 요건 '분기 1회 검토'에 문장 '연 1회'는 불충족)
- "~할 수 있다"는 임의 규정이므로 의무 요건("~하여야 한다")의 근거로 부족하다
- 대상이 일치하는 문장이 전혀 없으면 → "불충족"
- 대상은 일치하나 내용 충족 여부가 애매하면 → "판정불가"

출력 필드:
- "누락요소": 불충족일 때, 문서에서 찾지 못한 요건 내용
- "사유": 판정불가일 때 필수 — 무엇이 애매한지와 수동으로 확인할 것을 구체적으로 쓴다
  (예: "[2]가 비밀번호 변경을 다루나 변경 주기 수치가 없음 — 정책 원문에서 주기 확인 필요")
- "근거문장": 판정에 사용한 문장 번호 (판정불가도 검토한 문장 번호를 적는다)

반드시 아래 JSON만 출력:
{"verdict":"충족 또는 불충족 또는 판정불가","근거문장":[번호],"누락요소":"","사유":""}`
)

var jsonRe = regexp.MustCompile(`\{[^{}]*\}`)

// Client calls an LLM for inference — Claude Messages API (ANTHROPIC_API_KEY set)
// 또는 Ollama 서버(폴백). 메서드(Judge/EstimateCVSS/Available) 시그니처는 동일.
type Client struct {
	url        string // Ollama base URL, e.g. http://ollama:11434 (폴백용)
	apiKey     string // Anthropic API key — 있으면 Claude provider 사용
	model      string // Claude 모델명 또는 Ollama 태그
	httpClient *http.Client
}

// NewClient creates a new LLM client.
//   - ANTHROPIC_API_KEY 환경변수가 있으면 → Claude Messages API 사용
//     (모델: CLAUDE_MODEL 환경변수, 기본 claude-haiku-4-5-20251001)
//   - 없으면 → Ollama(url, model) 사용 (기존 동작)
//   - 둘 다 미설정이면 Available()=false → 모든 메서드 nil 반환(graceful)
func NewClient(url, model string) *Client {
	c := &Client{
		url:        url,
		model:      model,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		c.apiKey = key
		if m := os.Getenv("CLAUDE_MODEL"); m != "" {
			c.model = m
		} else if c.model == "" || strings.HasPrefix(c.model, "qwen") {
			c.model = "claude-haiku-4-5-20251001"
		}
	} else if c.model == "" {
		c.model = "qwen2.5:7b"
	}
	return c
}

// UsingClaude는 Claude API provider로 동작 중인지(=ANTHROPIC_API_KEY 설정됨) 반환합니다.
// 결측 보완(CVSS imputation)처럼 Ollama 폴백을 쓰지 않고 Claude만 허용하려는 호출부에서 게이팅용.
func (c *Client) UsingClaude() bool { return c != nil && c.apiKey != "" }

// Available returns true if either Claude(apiKey) or Ollama(url) is configured.
// ⚠ 설정 여부만 본다 — 서버가 실제로 떠 있는지는 보지 않는다. 실제 도달성은 Healthy를 써라.
func (c *Client) Available() bool {
	return c != nil && (c.apiKey != "" || c.url != "")
}

// Complete는 임의의 system+user 프롬프트를 LLM에 보내고 raw 응답 텍스트를 반환합니다(범용).
// 도메인 결합 없이 재사용 가능 — 가중치 추천·시나리오 등 호출부가 프롬프트/파싱을 담당.
// 미설정(Available=false) 시 에러를 반환합니다.
func (c *Client) Complete(ctx context.Context, system, user string, temperature float64) (string, error) {
	if !c.Available() {
		return "", fmt.Errorf("vlm: not configured")
	}
	return c.doChat(ctx, system, user, temperature)
}

// doChat은 provider(Claude/Ollama)로 system+user 프롬프트를 전송하고 raw 응답 텍스트를 반환합니다.
// 일시적 실패는 백오프 재시도. 모두 실패하면 ("", err).
func (c *Client) doChat(ctx context.Context, system, user string, temperature float64) (string, error) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(float64(initialRetryDelay) * math.Pow(2, float64(attempt-1)))
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(delay):
			}
		}
		var (
			raw string
			err error
		)
		if c.UsingClaude() {
			raw, err = c.chatClaude(ctx, system, user, temperature)
		} else {
			raw, err = c.chatOllama(ctx, system, user, temperature)
		}
		if err == nil {
			return raw, nil
		}
		lastErr = err
		log.Printf("[vlm] attempt %d/%d failed: %v", attempt+1, maxRetries, err)
	}
	return "", lastErr
}

// chatClaude — Anthropic Messages API (POST /v1/messages).
func (c *Client) chatClaude(ctx context.Context, system, user string, temperature float64) (string, error) {
	reqBody := map[string]any{
		"model":       c.model,
		"max_tokens":  1024,
		"temperature": temperature,
		"system":      system,
		"messages":    []map[string]string{{"role": "user", "content": user}},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("claude status %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	for _, blk := range out.Content {
		if blk.Type == "text" {
			return blk.Text, nil
		}
	}
	return "", fmt.Errorf("claude: empty text content")
}

// chatOllama — Ollama /api/chat (폴백).
func (c *Client) chatOllama(ctx context.Context, system, user string, temperature float64) (string, error) {
	chatReq := ollamaChatRequest{
		Model: c.model,
		Messages: []ollamaMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Stream:  false,
		Options: ollamaOptions{Temperature: temperature},
	}
	body, err := json.Marshal(chatReq)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama status %d: %s", resp.StatusCode, string(b))
	}
	var chatResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", err
	}
	return chatResp.Message.Content, nil
}

// Healthy reports whether the Ollama server is actually reachable right now
// (짧은 타임아웃 GET /api/tags). Available()이 설정 여부만 보는 것과 달리, 서버가 죽어 있으면
// false를 돌려준다. GL 평가 스킵 가드(스케줄러/Trigger)에서 "URL은 있는데 ollama가 죽은" 경우를
// 잡아 기존 결과를 보존하는 데 쓴다.
func (c *Client) Healthy(ctx context.Context) bool {
	if c == nil {
		return false
	}
	// Claude provider는 외부 ollama 서버가 없어도 사용 가능하다(도달 실패는 호출 시 graceful).
	// ollama 미배포(Claude 전용) 구성에서 GL 평가가 스킵되지 않도록 true로 간주한다.
	if c.UsingClaude() {
		return true
	}
	if c.url == "" {
		return false
	}
	hctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, strings.TrimRight(c.url, "/")+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode < 500
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
	Reason      string          `json:"사유"` // 판정불가 사유 (무엇이 애매한지·무엇을 수동 확인해야 하는지)
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
		// 유사도가 미상(음수 센티넬, 예: 텍스트 캐시 경로)이면 표기를 생략한다.
		if s.Score < 0 {
			fmt.Fprintf(&b, "[%d] %s\n", s.Index, s.Text)
		} else {
			fmt.Fprintf(&b, "[%d] %s (유사도: %.3f)\n", s.Index, s.Text, s.Score)
		}
	}

	b.WriteString("\n위 문장들이 룰 요건을 함의(충족)하는지 판정하라. 먼저 각 문장이 룰 요건의 대상을 직접 다루는지 확인하고, 대상이 다른 문장은 근거에서 제외하라. JSON만 출력.")
	return b.String()
}

// Judge sends a judgment request to the Ollama server and returns the verdict.
// Returns nil, nil if the client is unavailable or all retries fail (graceful degradation).
func (c *Client) Judge(ctx context.Context, req JudgeRequest) (*JudgeResponse, error) {
	if !c.Available() {
		return nil, nil
	}

	raw, err := c.doChat(ctx, systemPrompt, buildUserPrompt(req), 0.0)
	if err != nil {
		// 모든 재시도 실패 — graceful degradation.
		log.Printf("[vlm] judge failed: %v", err)
		return nil, nil
	}

	// Parse JSON from LLM raw text (same logic as colab_server.py).
	raw = strings.TrimSpace(raw)
	log.Printf("[vlm] raw response: %s", raw)
	result := parseJudgeJSON(raw)
	return &result, nil
}

// parseJudgeJSON extracts the first JSON object from LLM output and maps it to JudgeResponse.
func parseJudgeJSON(raw string) JudgeResponse {
	fallback := JudgeResponse{
		Verdict:     "판정불가",
		RawBasis:    json.RawMessage(`[]`),
		MissingElem: "",
		Reason:      "LLM 응답에서 JSON 추출 실패 — 모델 출력 형식 오류",
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
