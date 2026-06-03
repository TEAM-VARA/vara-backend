package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

// defaultEmbeddingMinCosine is used when ruleset similarity_threshold is 0 or unset.
func defaultEmbeddingMinCosine() float64 {
	if v := strings.TrimSpace(os.Getenv("GRC_EMBEDDING_MIN_COSINE")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			return f
		}
	}
	return 0.68
}

func ruleEmbeddingThreshold(rule Rule) float64 {
	t := rule.JudgmentLogic.SimilarityThreshold
	if t > 0 && t <= 1 {
		return t
	}
	return defaultEmbeddingMinCosine()
}

// cosineSimilarity returns cosine of angle between two vectors (range [-1,1]).
func cosineSimilarity(a, b []float32) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		ai, bi := float64(a[i]), float64(b[i])
		dot += ai * bi
		na += ai * ai
		nb += bi * bi
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// evaluateEmbeddingSimilarity embeds evidence text and this rule's guideline text, then compares cosine to threshold.
func (s *GRCService) evaluateEmbeddingSimilarity(ctx context.Context, rule Rule, evidenceData []any, base grc.RuleResult) grc.RuleResult {
	if s.embeddingClient == nil || !s.embeddingClient.Available() {
		base.Verdict = "skipped"
		base.SkipReason = "임베딩 서버 비가동 (embedding_similarity_with_threshold)"
		return base
	}
	var evText strings.Builder
	for _, d := range evidenceData {
		switch v := d.(type) {
		case string:
			evText.WriteString(v)
			evText.WriteString("\n")
		case map[string]any:
			if b, err := json.Marshal(v); err == nil {
				evText.Write(b)
				evText.WriteString("\n")
			}
		}
	}
	text := strings.TrimSpace(evText.String())
	if text == "" {
		base.Verdict = "skipped"
		base.SkipReason = "임베딩 비교용 증적 텍스트 없음"
		return base
	}
	guide := buildGuidelineText(rule)
	if strings.TrimSpace(guide) == "" {
		base.Verdict = "skipped"
		base.SkipReason = "룰 지침 텍스트 비어 있음"
		return base
	}
	embs, err := s.embeddingClient.EmbedBatch(ctx, []string{text, guide})
	if err != nil || len(embs) < 2 || embs[0] == nil || embs[1] == nil {
		base.Verdict = "skipped"
		base.SkipReason = "임베딩 생성 실패"
		return base
	}
	sim := cosineSimilarity(embs[0], embs[1])
	th := ruleEmbeddingThreshold(rule)
	if sim >= th {
		base.Verdict = "준수"
		base.MatchedIndicators = []string{fmt.Sprintf("임베딩 유사도 %.3f ≥ 임계 %.3f (증적↔룰 지침)", sim, th)}
	} else {
		base.Verdict = "미준수"
		base.Violations = []grc.Violation{{
			Description: fmt.Sprintf("임베딩 유사도 %.3f < 임계 %.3f (증적 내용이 룰 지침 맥락과 불일치)", sim, th),
			Severity:    "medium",
		}}
	}
	return base
}

// applyGuidelineEmbedding compares evidence embeddings against guideline embeddings.
// Uses DB guideline embeddings when available, otherwise falls back to rule-based text embedding.
// If primary verdict was 준수 but similarity is below threshold, downgrades to 미준수.
func (s *GRCService) applyGuidelineEmbedding(
	rule Rule,
	matched []grc.EvidenceFile,
	embByFile map[string][]float32,
	dbGuidelines []grc.Guideline,
	primary grc.RuleResult,
) grc.RuleResult {
	// 1차가 이미 증적↔지침 임베딩 유사도만으로 판정한 경우 중복 호출 방지
	if rule.JudgmentLogic.Type == "semantic_match" &&
		(strings.EqualFold(rule.JudgmentLogic.Method, "embedding_similarity_with_threshold") ||
			strings.EqualFold(rule.JudgmentLogic.Method, "llm_rag_entailment")) {
		return primary
	}
	if primary.Verdict == "skipped" {
		return primary
	}
	if len(embByFile) == 0 {
		primary.MatchedIndicators = append(primary.MatchedIndicators,
			"임베딩 검증: DB에 증적 벡터 없음(스킵)")
		return primary
	}

	// Collect guideline embeddings from DB.
	var guidelineEmbs [][]float32
	for _, g := range dbGuidelines {
		if len(g.Embedding) > 0 {
			guidelineEmbs = append(guidelineEmbs, g.Embedding)
		}
	}

	if len(guidelineEmbs) == 0 {
		primary.MatchedIndicators = append(primary.MatchedIndicators,
			"임베딩 검증: 지침 임베딩 없음(스킵)")
		return primary
	}

	th := ruleEmbeddingThreshold(rule)

	// Compare each evidence file against all guideline embeddings, take max per evidence.
	var bestSims []float64
	for _, ef := range matched {
		ev, ok := embByFile[ef.Filename]
		if !ok || len(ev) == 0 {
			continue
		}
		var maxSim float64
		for _, gEmb := range guidelineEmbs {
			if len(ev) != len(gEmb) {
				continue
			}
			sim := cosineSimilarity(ev, gEmb)
			if sim > maxSim {
				maxSim = sim
			}
		}
		bestSims = append(bestSims, maxSim)
	}

	if len(bestSims) == 0 {
		primary.MatchedIndicators = append(primary.MatchedIndicators,
			"임베딩 검증: 매칭 증적에 저장된 벡터 없음(스킵)")
		return primary
	}

	// Use max similarity across all evidence files.
	maxSim := bestSims[0]
	for _, x := range bestSims[1:] {
		if x > maxSim {
			maxSim = x
		}
	}

	primary.EmbeddingSimilarity = &maxSim

	if maxSim < th {
		msg := fmt.Sprintf("임베딩: 증적↔지침 코사인 최대 %.3f < 임계 %.3f (의미 정합성 부족)", maxSim, th)
		if primary.Verdict == "준수" {
			primary.Verdict = "미준수"
			primary.Violations = append(primary.Violations, grc.Violation{
				Description: msg,
				Severity:    "medium",
			})
		} else {
			primary.MatchedIndicators = append(primary.MatchedIndicators, msg)
		}
	} else {
		primary.MatchedIndicators = append(primary.MatchedIndicators,
			fmt.Sprintf("임베딩 검증 통과 (증적↔지침 코사인 최대 %.3f ≥ %.3f)", maxSim, th))
	}
	return primary
}
