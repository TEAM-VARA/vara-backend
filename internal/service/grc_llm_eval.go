package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/platform/vlm"
)

const defaultRAGTopK = 3

// scoredSentence holds a guideline sentence with its cosine similarity score.
type scoredSentence struct {
	index int
	text  string
	score float64
}

// evaluateLLMRAGEntailment performs RAG + LLM entailment judgment:
//  1. Collect sentences from DB guidelines (GL-rule) or evidence text (R-rule)
//  2. Retrieve top-k sentences via BGE-M3 cosine similarity
//  3. Call VLM (Qwen on Colab) for entailment judgment
//  4. Map verdict to grc.RuleResult
func (s *GRCService) evaluateLLMRAGEntailment(
	ctx context.Context,
	rule Rule,
	dbGuidelines []grc.Guideline,
	evidenceData []any,
	base grc.RuleResult,
) grc.RuleResult {

	// ── Guard: VLM client must be available ──
	if s.vlmClient == nil || !s.vlmClient.Available() {
		base.Verdict = "skipped"
		base.SkipReason = "VLM 서버 비가동 (llm_rag_entailment)"
		return base
	}

	// ── Guard: embedding client must be available for retrieval ──
	if s.embeddingClient == nil || !s.embeddingClient.Available() {
		base.Verdict = "skipped"
		base.SkipReason = "임베딩 서버 비가동 (retrieval 불가)"
		return base
	}

	// ── Step 1: Collect sentences ──
	// text_extraction (GL-rule): sentences from DB guidelines
	// k8s_api / other: sentences from uploaded evidence text
	var sentences []string
	if rule.JudgmentSource == "text_extraction" {
		sentences = splitGuidelineSentences(dbGuidelines, rule)
	} else {
		sentences = splitEvidenceSentences(evidenceData)
	}
	if len(sentences) == 0 {
		if rule.JudgmentSource == "text_extraction" {
			base.Verdict = "skipped"
			base.SkipReason = "지침 문장 없음 (DB 지침 미등록)"
		} else {
			base.Verdict = "skipped"
			base.SkipReason = "증적 텍스트 없음 (PDF 추출 실패 또는 미업로드)"
		}
		return base
	}

	// ── Step 2: Build query from rule ──
	query := buildRuleQuery(rule)
	if query == "" {
		base.Verdict = "skipped"
		base.SkipReason = "룰 요건 텍스트 비어 있음"
		return base
	}

	// ── Step 3: Embed query + all guideline sentences ──
	textsToEmbed := append([]string{query}, sentences...)
	embeddings, err := s.embeddingClient.EmbedBatch(ctx, textsToEmbed)
	if err != nil || len(embeddings) < 2 || embeddings[0] == nil {
		base.Verdict = "skipped"
		base.SkipReason = "임베딩 생성 실패"
		return base
	}

	queryEmb := embeddings[0]

	// ── Step 4: Cosine similarity retrieval (top-k) ──
	var scored []scoredSentence
	for i := 1; i < len(embeddings); i++ {
		if embeddings[i] == nil {
			continue
		}
		sim := cosineSimilarity(queryEmb, embeddings[i])
		scored = append(scored, scoredSentence{
			index: i - 1,
			text:  sentences[i-1],
			score: sim,
		})
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	topK := defaultRAGTopK
	if topK > len(scored) {
		topK = len(scored)
	}
	topHits := scored[:topK]

	for rank, hit := range topHits {
		log.Printf("[grc-rag] rule=%s rank=%d cos=%.3f sentence=%q",
			rule.RuleID, rank+1, hit.score, ragTruncate(hit.text, 60))
	}

	// ── Step 5: Build VLM judge request ──
	var retrieved []vlm.RetrievedSentence
	for i, hit := range topHits {
		retrieved = append(retrieved, vlm.RetrievedSentence{
			Index: i + 1,
			Text:  hit.text,
			Score: hit.score,
		})
	}

	polarity, params := extractRulePolarity(rule)

	judgeReq := vlm.JudgeRequest{
		RuleRequirement:    query,
		Polarity:           polarity,
		Parameters:         params,
		RetrievedSentences: retrieved,
	}

	// ── Debug: VLM 요청 로깅 ──
	if reqJSON, err := json.Marshal(judgeReq); err == nil {
		log.Printf("[grc-rag] VLM REQUEST rule=%s:\n%s", rule.RuleID, string(reqJSON))
	}

	// ── Step 6: Call VLM for entailment judgment ──
	judgeResp, err := s.vlmClient.Judge(ctx, judgeReq)
	if err != nil {
		log.Printf("[grc-rag] VLM judge error: %v", err)
		base.Verdict = "skipped"
		base.SkipReason = fmt.Sprintf("VLM 판정 오류: %v", err)
		return base
	}
	if judgeResp == nil {
		base.Verdict = "skipped"
		base.SkipReason = "VLM 서버 응답 없음 (연결 실패)"
		return base
	}

	// ── Debug: VLM 응답 로깅 ──
	if respJSON, err := json.Marshal(judgeResp); err == nil {
		log.Printf("[grc-rag] VLM RESPONSE rule=%s:\n%s", rule.RuleID, string(respJSON))
	}

	// ── Step 7: Map VLM verdict → grc.RuleResult ──
	return mapVLMVerdictToResult(judgeResp, topHits, base)
}

// splitEvidenceSentences extracts text from evidence data and splits into sentences.
// Used when R-rules use llm_rag_entailment with uploaded evidence (PDF text) as the source.
func splitEvidenceSentences(evidenceData []any) []string {
	var allText strings.Builder
	for _, d := range evidenceData {
		switch v := d.(type) {
		case string:
			allText.WriteString(v)
			allText.WriteString("\n")
		case map[string]any:
			// Extract text fields from structured evidence
			for _, key := range []string{"text", "content", "extracted_text"} {
				if t, ok := v[key].(string); ok && t != "" {
					allText.WriteString(t)
					allText.WriteString("\n")
				}
			}
		}
	}

	raw := strings.TrimSpace(allText.String())
	if raw == "" {
		return nil
	}

	var sentences []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "---" {
			continue
		}
		if len([]rune(line)) > 5 {
			sentences = append(sentences, line)
		}
	}
	return sentences
}

// splitGuidelineSentences breaks DB guideline extracted_text into individual sentences.
// Falls back to buildGuidelineText(rule) if no DB guidelines exist.
func splitGuidelineSentences(dbGuidelines []grc.Guideline, rule Rule) []string {
	var allText string
	for _, g := range dbGuidelines {
		if g.ExtractedText != "" {
			allText += g.ExtractedText + "\n"
		}
	}

	if allText == "" {
		allText = buildGuidelineText(rule)
	}

	if strings.TrimSpace(allText) == "" {
		return nil
	}

	// Split by newlines, filter empty/trivial fragments.
	var sentences []string
	for _, line := range strings.Split(allText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "---" {
			continue
		}
		if len([]rune(line)) > 5 {
			sentences = append(sentences, line)
		}
	}
	return sentences
}

// buildRuleQuery constructs the query text from rule fields for embedding retrieval.
func buildRuleQuery(rule Rule) string {
	if rule.Name != "" {
		return rule.Name
	}
	var parts []string
	for _, ind := range rule.ComplianceIndicators {
		if ind.Description != "" {
			parts = append(parts, ind.Description)
		}
	}
	return strings.Join(parts, " ")
}

// extractRulePolarity extracts polarity and parameters from the rule for VLM judgment.
func extractRulePolarity(rule Rule) (string, map[string]string) {
	polarity := "must"

	params := make(map[string]string)
	for _, ind := range rule.ComplianceIndicators {
		if ind.Field != "" && ind.Value != nil {
			params[ind.Field] = fmt.Sprintf("%v", ind.Value)
		}
	}

	return polarity, params
}

// mapVLMVerdictToResult converts the VLM response into a grc.RuleResult.
func mapVLMVerdictToResult(resp *vlm.JudgeResponse, topHits []scoredSentence, base grc.RuleResult) grc.RuleResult {
	switch resp.Verdict {
	case "충족":
		base.Verdict = "준수"
		var indicators []string
		indicators = append(indicators, fmt.Sprintf("LLM 판정: 충족 (양태: %s)", resp.Modality))
		for _, idx := range resp.BasisIdx {
			if idx >= 1 && idx <= len(topHits) {
				hit := topHits[idx-1]
				indicators = append(indicators, fmt.Sprintf("근거[%d]: %s (cos=%.3f)", idx, ragTruncate(hit.text, 80), hit.score))
			}
		}
		base.MatchedIndicators = indicators

	case "부분":
		base.Verdict = "검토필요"
		var indicators []string
		indicators = append(indicators, fmt.Sprintf("LLM 판정: 부분충족 (양태: %s)", resp.Modality))
		if resp.MissingElem != "" {
			indicators = append(indicators, fmt.Sprintf("누락요소: %s", resp.MissingElem))
		}
		base.MatchedIndicators = indicators

	case "불충족":
		base.Verdict = "미준수"
		desc := fmt.Sprintf("LLM 판정: 불충족 (양태: %s)", resp.Modality)
		if resp.MissingElem != "" {
			desc += fmt.Sprintf(" / 누락요소: %s", resp.MissingElem)
		}
		base.Violations = []grc.Violation{{
			Description: desc,
			Severity:    "high",
		}}

	default: // 판정불가
		base.Verdict = "검토필요"
		base.MatchedIndicators = []string{"LLM 판정: 판정불가 (수동 검토 필요)"}
	}

	return base
}

func ragTruncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
