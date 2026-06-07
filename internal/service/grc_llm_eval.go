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

// scoreUnknown marks a retrieved sentence whose true cosine score is unavailable
// (e.g. served from the top-K text cache, which stores sentence text only — not
// scores). Renderers, the VLM prompt, and evidence JSON must OMIT similarity when
// the score is this sentinel instead of fabricating a perfect 1.000.
const scoreUnknown = -1.0

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
			// 캐시는 문장 텍스트만 보관하고 cosine score는 보존하지 않는다.
			// 거짓 1.000 대신 '미상' 센티넬을 부여해 표기/프롬프트에서 생략한다.
			topHits = append(topHits, scoredSentence{index: i, text: s, score: scoreUnknown})
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
		return mapVLMVerdictToResult(judgeResp, topHits, base, rule)
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
			base.Reason = fmt.Sprintf("지침 미등록 — 『%s』 문서 업로드 필요", policyDocHint(glItemID(rule, base)))
			attachGLPolicyGuidance(rule, &base, "")
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
	return mapVLMVerdictToResult(judgeResp, topHits, base, rule)
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
func mapVLMVerdictToResult(resp *vlm.JudgeResponse, topHits []scoredSentence, base grc.RuleResult, rule Rule) grc.RuleResult {
	verdict := resp.Verdict
	base.Layer = grc.LayerGL

	// ── "부분"도 "충족"으로 통합: 관련 내용이 있으면 충족 ──
	if verdict == "부분" {
		log.Printf("[grc-rag] post-fix: 부분→충족 (내용 존재 시 충족 정책)")
		verdict = "충족"
	}

	switch verdict {
	case "충족":
		base.Verdict = grc.VerdictMET
		base.Reason = fmt.Sprintf("LLM 충족 판정, 근거 문장 %d건", len(resp.BasisIdx))
		var indicators []string
		indicators = append(indicators, "LLM 판정: 충족")
		// Build evidence_data JSON
		type evidenceEntry struct {
			SentenceIndex int      `json:"sentence_index"`
			Text          string   `json:"text"`
			CosineScore   *float64 `json:"cosine_score,omitempty"`
		}
		var evidenceEntries []evidenceEntry
		for _, idx := range resp.BasisIdx {
			if idx >= 1 && idx <= len(topHits) {
				hit := topHits[idx-1]
				entry := evidenceEntry{SentenceIndex: hit.index, Text: hit.text}
				// score가 미상(캐시 경로)이면 cos 표기를 생략한다 (거짓 1.000 방지).
				if hit.score >= 0 {
					indicators = append(indicators, fmt.Sprintf("근거[%d]: %s (cos=%.3f)", idx, ragTruncate(hit.text, 80), hit.score))
					sc := hit.score
					entry.CosineScore = &sc
				} else {
					indicators = append(indicators, fmt.Sprintf("근거[%d]: %s", idx, ragTruncate(hit.text, 80)))
				}
				evidenceEntries = append(evidenceEntries, entry)
			}
		}
		base.MatchedIndicators = indicators
		if ej, err := json.Marshal(evidenceEntries); err == nil {
			base.EvidenceData = ej
		}

	case "불충족":
		// 거짓 불충족 방어: LLM이 '누락'으로 지목한 요소가 실제로 근거 문장에
		// 존재하면 자동 불충족을 신뢰할 수 없으므로 수동 검토로 보정한다.
		// (missingFoundInBasis는 동의어·부분 키워드 매칭이라 자동 '충족' 단정은
		//  거짓 음성 위험이 있어, 안전하게 NEEDS_REVIEW로만 강등한다.)
		if resp.MissingElem != "" && missingFoundInBasis(resp.MissingElem, resp.BasisIdx, topHits) {
			log.Printf("[grc-rag] post-fix: 불충족→검토필요 (누락 지목 '%s'이(가) 근거 문장에 존재)", resp.MissingElem)
			base.Verdict = grc.VerdictNEEDS_REVIEW
			base.Reason = fmt.Sprintf("LLM은 '%s' 누락으로 판정했으나 근거 문장에 관련 내용이 있어 수동 검토 필요", resp.MissingElem)
			base.MatchedIndicators = []string{fmt.Sprintf("판정 보정: '%s' 누락 판정 — 근거 문장에 관련 표현 존재(수동 검토 필요)", resp.MissingElem)}
			attachGLPolicyGuidance(rule, &base, resp.MissingElem)
			return base
		}
		base.Verdict = grc.VerdictNOT_MET
		desc := "LLM 판정: 불충족"
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
		attachGLPolicyGuidance(rule, &base, resp.MissingElem)

	default: // 판정불가
		base.Verdict = grc.VerdictINDETERMINATE
		base.Reason = "LLM 판정불가 (수동 검토)"
		base.MatchedIndicators = []string{"LLM 판정: 판정불가 (수동 검토 필요)"}
		attachGLPolicyGuidance(rule, &base, "")
	}

	return base
}

// glItemID resolves the ISMS-P item ID for a GL rule, deriving it from the
// rule ID (e.g. "R-2.5.4-GL03" → "2.5.4") when the base result lacks one.
func glItemID(rule Rule, base grc.RuleResult) string {
	if base.ISMSPItemID != "" {
		return base.ISMSPItemID
	}
	id := strings.TrimPrefix(rule.RuleID, "R-")
	if i := strings.LastIndex(id, "-"); i > 0 {
		return id[:i]
	}
	return id
}

// policyDocHint returns the recommended policy/standard document name an
// organization should maintain for the given ISMS-P item.
func policyDocHint(itemID string) string {
	hints := map[string]string{
		"1.2.1":  "정보자산 관리 지침·자산 분류 기준서",
		"1.2.2":  "정보서비스·개인정보 흐름도(현황 및 흐름분석 문서)",
		"2.1.3":  "정보자산 관리 지침(자산별 책임자·보안등급 취급절차)",
		"2.5.1":  "사용자 계정 관리 지침",
		"2.5.2":  "사용자 식별 기준(계정 명명·공유계정 규정)",
		"2.5.4":  "비밀번호 관리 정책/지침",
		"2.5.5":  "특수 계정 및 권한 관리 지침",
		"2.6.1":  "네트워크 접근통제 지침(망 분리 설계 기준)",
		"2.6.3":  "응용프로그램 접근통제 지침",
		"2.6.7":  "인터넷 접속 통제 정책",
		"2.7.1":  "암호정책(암호화 대상·알고리즘·키 관리 기준)",
		"2.8.3":  "개발·운영 환경 분리 지침",
		"2.9.1":  "변경관리 절차서",
		"2.10.2": "클라우드 보안 지침",
		"2.10.3": "공개서버 보안 지침",
		"2.10.5": "정보전송 보안 정책(조직 간 전송 협약 기준 포함)",
		"2.10.8": "패치관리 절차서",
		"2.11.3": "이상행위 분석·모니터링 지침(로그 관리 정책)",
	}
	if h, ok := hints[itemID]; ok {
		return h
	}
	return "해당 항목 관련 정책·지침"
}

// glRequiredContents collects the provisions the policy document must contain
// for a GL rule (rule name + indicator descriptions, deduplicated).
func glRequiredContents(rule Rule) []string {
	var req []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		req = append(req, s)
	}
	add(rule.Name)
	for _, ind := range rule.ComplianceIndicators {
		add(ind.Description)
	}
	return req
}

// attachGLPolicyGuidance attaches "어떤 내용이 담긴 어떤 정책서가 필요한가" guidance
// to a failed/indeterminate GL result — mirroring the off-cluster guidance(⚡/📋)
// that R rules carry via ManualCheckOutput metadata.
func attachGLPolicyGuidance(rule Rule, res *grc.RuleResult, missingElem string) {
	doc := policyDocHint(glItemID(rule, *res))
	req := glRequiredContents(rule)

	res.Remediation = fmt.Sprintf("『%s』 등 사내 정책·지침에 다음 내용을 명문화하세요: %s", doc, strings.Join(req, " / "))
	if missingElem != "" {
		res.Remediation += fmt.Sprintf(" — 누락 확인: %s", missingElem)
	}

	// 프론트/CLI가 R룰과 동일하게 렌더링하도록 MCO 필드 재사용
	if b, err := json.Marshal([]string{doc}); err == nil {
		res.ManualCheckAreas = b
	}
	items := make([]string, 0, len(req)+1)
	items = append(items, fmt.Sprintf("필요 문서: 『%s』", doc))
	for _, r := range req {
		items = append(items, "정책서 반영 필요: "+r)
	}
	if b, err := json.Marshal(items); err == nil {
		res.AdditionalReviewItems = b
	}
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

// ensureVerdictDisplay guarantees a renderable indicator for INDETERMINATE
// results. Several early-return paths (VLM/임베딩 비가동, 증적·지침 문장 없음 등)
// set only Reason/SkipReason and leave MatchedIndicators empty, which renders as
// a blank line after the "[INDETERMINATE]" tag. Fill it from the reason text so
// the verdict always carries a human-readable explanation.
func ensureVerdictDisplay(rr grc.RuleResult) grc.RuleResult {
	if len(rr.MatchedIndicators) > 0 {
		return rr
	}
	if grc.NormalizeVerdict(rr.Verdict) != grc.VerdictINDETERMINATE {
		return rr
	}
	msg := strings.TrimSpace(rr.Reason)
	if msg == "" {
		msg = strings.TrimSpace(rr.SkipReason)
	}
	if msg == "" {
		msg = "판정불가 (수동 검토 필요)"
	}
	rr.MatchedIndicators = []string{msg}
	return rr
}

// dedupRuleResultsByID collapses results that share a RuleID (e.g. a rule
// accidentally evaluated twice within one check), keeping the most informative
// verdict: a definitive NOT_MET/MET wins over NEEDS_REVIEW/INDETERMINATE/NO_DATA,
// and among equally-ranked results the later one wins. Results without a RuleID
// are passed through untouched.
//
// NOTE: only safe where each RuleID is expected at most once (the GL/per-item
// check loop). Do NOT use on the cluster per-pod path, where many pods
// legitimately share a RuleID.
func dedupRuleResultsByID(results []grc.RuleResult) []grc.RuleResult {
	idx := make(map[string]int, len(results))
	out := make([]grc.RuleResult, 0, len(results))
	for _, r := range results {
		if r.RuleID == "" {
			out = append(out, r)
			continue
		}
		if pos, ok := idx[r.RuleID]; ok {
			if verdictInformativeness(r.Verdict) >= verdictInformativeness(out[pos].Verdict) {
				out[pos] = r
			}
			continue
		}
		idx[r.RuleID] = len(out)
		out = append(out, r)
	}
	return out
}

// verdictInformativeness ranks verdicts for dedup tie-breaking. A confirmed
// defect (NOT_MET) is the most informative and must never be hidden behind a
// duplicate INDETERMINATE evaluation of the same rule.
func verdictInformativeness(v string) int {
	switch grc.NormalizeVerdict(v) {
	case grc.VerdictNOT_MET:
		return 4
	case grc.VerdictMET:
		return 3
	case grc.VerdictNEEDS_REVIEW:
		return 2
	case grc.VerdictNO_DATA, grc.VerdictINDETERMINATE:
		return 1
	default:
		return 0
	}
}
