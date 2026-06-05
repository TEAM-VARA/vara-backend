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

const defaultRAGTopK = 5

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
// cachedGLSentences: pre-computed top-K sentences from precomputeGLRuleTopSentences.
// When non-nil, Steps 1–4 (sentence collection + embedding + cosine similarity) are skipped.
func (s *GRCService) evaluateLLMRAGEntailment(
	ctx context.Context,
	rule Rule,
	dbGuidelines []grc.Guideline,
	evidenceData []any,
	base grc.RuleResult,
	cachedGLSentences []string,
) grc.RuleResult {

	base.Layer = grc.LayerGL

	// ── Guard: VLM client must be available ──
	if s.vlmClient == nil || !s.vlmClient.Available() {
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = "VLM 서버 비가동 (llm_rag_entailment)"
		base.Reason = "VLM 서버 비가동"
		return base
	}

	// ── Fast path: use pre-computed top sentences (skip embedding entirely) ──
	if len(cachedGLSentences) > 0 {
		log.Printf("[grc-rag] rule=%s: cache HIT, skipping embedding (%d sentences)", rule.RuleID, len(cachedGLSentences))
		var topHits []scoredSentence
		for i, s := range cachedGLSentences {
			topHits = append(topHits, scoredSentence{index: i, text: s, score: 1.0})
		}
		query := buildRuleQuery(rule)
		polarity, params := extractRulePolarity(rule)
		var retrieved []vlm.RetrievedSentence
		for i, hit := range topHits {
			retrieved = append(retrieved, vlm.RetrievedSentence{Index: i + 1, Text: hit.text, Score: hit.score})
		}
		judgeReq := vlm.JudgeRequest{
			RuleRequirement:    query,
			Polarity:           polarity,
			Parameters:         params,
			RetrievedSentences: retrieved,
		}
		if reqJSON, err := json.Marshal(judgeReq); err == nil {
			log.Printf("[grc-rag] VLM REQUEST (cached) rule=%s:\n%s", rule.RuleID, string(reqJSON))
		}
		judgeResp, err := s.vlmClient.Judge(ctx, judgeReq)
		if err != nil || judgeResp == nil {
			base.Verdict = grc.VerdictINDETERMINATE
			base.SkipReason = fmt.Sprintf("VLM 판정 오류: %v", err)
			base.Reason = "VLM 판정 오류"
			return base
		}
		if respJSON, err := json.Marshal(judgeResp); err == nil {
			log.Printf("[grc-rag] VLM RESPONSE (cached) rule=%s:\n%s", rule.RuleID, string(respJSON))
		}
		return mapVLMVerdictToResult(judgeResp, topHits, base)
	}

	// ── Guard: embedding client must be available for retrieval ──
	if s.embeddingClient == nil || !s.embeddingClient.Available() {
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = "임베딩 서버 비가동 (retrieval 불가)"
		base.Reason = "임베딩 서버 비가동"
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
			base.Verdict = grc.VerdictINDETERMINATE
			base.SkipReason = "지침 문장 없음 (DB 지침 미등록)"
			base.Reason = "지침 미등록"
		} else {
			base.Verdict = grc.VerdictINDETERMINATE
			base.SkipReason = "증적 텍스트 없음 (PDF 추출 실패 또는 미업로드)"
			base.Reason = "증적 텍스트 없음"
		}
		return base
	}

	// ── Step 2: Build query from rule ──
	query := buildRuleQuery(rule)
	if query == "" {
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = "룰 요건 텍스트 비어 있음"
		base.Reason = "룰셋 데이터 오류 — 평가 기준 텍스트 없음"
		return base
	}

	// ── Step 2.5: Cap sentence count to prevent BGE-M3 CPU timeout ──
	// A 192K-char PDF splits into 3000+ sentences; embedding all at once can take 30+ min on CPU.
	// We use distributed sampling (every N-th sentence) to cover the whole document.
	const maxSentencesForRAG = 300
	if len(sentences) > maxSentencesForRAG {
		origLen := len(sentences)
		sampled := make([]string, 0, maxSentencesForRAG)
		step := len(sentences) / maxSentencesForRAG
		for i := 0; i < len(sentences) && len(sampled) < maxSentencesForRAG; i += step {
			sampled = append(sampled, sentences[i])
		}
		sentences = sampled
		log.Printf("[grc-rag] rule=%s: capped %d→%d sentences (every %d-th, distributed sample)",
			rule.RuleID, origLen, len(sentences), step)
	}

	// ── Step 3: Embed query + sampled guideline sentences ──
	textsToEmbed := append([]string{query}, sentences...)
	embeddings, err := s.embeddingClient.EmbedBatch(ctx, textsToEmbed)
	if err != nil || len(embeddings) < 2 || embeddings[0] == nil {
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = "임베딩 생성 실패 (서버 응답 없음 또는 타임아웃)"
		base.Reason = "임베딩 생성 실패"
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
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = fmt.Sprintf("VLM 판정 오류: %v", err)
		base.Reason = fmt.Sprintf("VLM 판정 오류: %v", err)
		return base
	}
	if judgeResp == nil {
		base.Verdict = grc.VerdictINDETERMINATE
		base.SkipReason = "VLM 서버 응답 없음 (연결 실패)"
		base.Reason = "VLM 서버 응답 없음"
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
	verdict := resp.Verdict
	base.Layer = grc.LayerGL

	// ── 후처리: "부분"인데 누락요소가 근거문장에 이미 있으면 "충족"으로 보정 ──
	if verdict == "부분" && resp.MissingElem != "" && len(resp.BasisIdx) > 0 {
		if missingFoundInBasis(resp.MissingElem, resp.BasisIdx, topHits) {
			log.Printf("[grc-rag] post-fix: 부분→충족 (누락요소 %q가 근거문장에 존재)", resp.MissingElem)
			verdict = "충족"
		}
	}

	switch verdict {
	case "충족":
		base.Verdict = grc.VerdictMET
		base.Reason = fmt.Sprintf("LLM 충족 판정, 근거 문장 %d건", len(resp.BasisIdx))
		var indicators []string
		indicators = append(indicators, fmt.Sprintf("LLM 판정: 충족 (양태: %s)", resp.Modality))
		// Build evidence_data JSON
		type evidenceEntry struct {
			SentenceIndex int     `json:"sentence_index"`
			Text          string  `json:"text"`
			CosineScore   float64 `json:"cosine_score"`
		}
		var evidenceEntries []evidenceEntry
		for _, idx := range resp.BasisIdx {
			if idx >= 1 && idx <= len(topHits) {
				hit := topHits[idx-1]
				indicators = append(indicators, fmt.Sprintf("근거[%d]: %s (cos=%.3f)", idx, ragTruncate(hit.text, 80), hit.score))
				evidenceEntries = append(evidenceEntries, evidenceEntry{
					SentenceIndex: hit.index,
					Text:          hit.text,
					CosineScore:   hit.score,
				})
			}
		}
		base.MatchedIndicators = indicators
		if ej, err := json.Marshal(evidenceEntries); err == nil {
			base.EvidenceData = ej
		}

	case "부분":
		base.Verdict = grc.VerdictNEEDS_REVIEW
		base.Reason = fmt.Sprintf("LLM 부분충족, 누락요소: %s", resp.MissingElem)
		var indicators []string
		indicators = append(indicators, fmt.Sprintf("LLM 판정: 부분충족 (양태: %s)", resp.Modality))
		if resp.MissingElem != "" {
			indicators = append(indicators, fmt.Sprintf("누락요소: %s", resp.MissingElem))
		}
		base.MatchedIndicators = indicators

	case "불충족":
		base.Verdict = grc.VerdictNOT_MET
		desc := fmt.Sprintf("LLM 판정: 불충족 (양태: %s)", resp.Modality)
		if resp.MissingElem != "" {
			desc += fmt.Sprintf(" / 누락요소: %s", resp.MissingElem)
			base.Reason = fmt.Sprintf("LLM 불충족, 누락요소: %s", resp.MissingElem)
		} else {
			base.Reason = "LLM 불충족"
		}
		base.Violations = []grc.Violation{{
			Description: desc,
			Severity:    "high",
		}}

	default: // 판정불가
		base.Verdict = grc.VerdictINDETERMINATE
		base.Reason = "LLM 판정불가 (수동 검토)"
		base.MatchedIndicators = []string{"LLM 판정: 판정불가 (수동 검토 필요)"}
	}

	return base
}

// missingFoundInBasis checks if the "missing element" text is actually present
// in the basis sentences. Handles synonym matching for common Korean compliance terms.
func missingFoundInBasis(missing string, basisIdx []int, topHits []scoredSentence) bool {
	// 동의어 매핑: LLM이 누락이라 한 표현 → 실제 문장에 있을 수 있는 표현들
	synonyms := map[string][]string{
		"즉시 회수":    {"즉시 회수", "즉시 반환", "회수한다"},
		"즉시 회수 조항": {"즉시 회수", "즉시 반환", "회수한다"},
		"승인 절차":    {"승인 절차", "승인을 거치", "별도 승인"},
		"공동 사용 금지": {"공용", "공유", "공동 사용", "금지한다"},
		"로깅":       {"로깅", "로그", "기록한다", "사용 내역"},
		"로깅 확보":    {"로깅", "로그", "기록한다", "사용 내역"},
	}

	// 근거문장 텍스트 수집
	var basisTexts []string
	for _, idx := range basisIdx {
		if idx >= 1 && idx <= len(topHits) {
			basisTexts = append(basisTexts, topHits[idx-1].text)
		}
	}
	if len(basisTexts) == 0 {
		return false
	}

	combined := strings.Join(basisTexts, " ")

	// 1) 누락요소 키워드를 동의어로 분해하여 검색
	for key, syns := range synonyms {
		if strings.Contains(missing, key) {
			for _, syn := range syns {
				if strings.Contains(combined, syn) {
					return true
				}
			}
		}
	}

	// 2) 누락요소 텍스트를 공백으로 분리하여 개별 키워드 검색
	//    키워드의 절반 이상이 근거문장에 있으면 이미 포함된 것으로 판단
	keywords := strings.Fields(missing)
	if len(keywords) == 0 {
		return false
	}
	matched := 0
	for _, kw := range keywords {
		if len([]rune(kw)) < 2 {
			continue // 조사/접속사 무시
		}
		if strings.Contains(combined, kw) {
			matched++
		}
	}
	return matched > 0 && matched >= (len(keywords)+1)/2
}

func ragTruncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
