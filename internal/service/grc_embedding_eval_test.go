package service

import (
	"math"
	"strings"
	"testing"
)

// ── cosineSimilarity ──

func TestCosineSimilarity_Identical(t *testing.T) {
	a := []float32{1, 2, 3}
	sim := cosineSimilarity(a, a)
	if math.Abs(sim-1.0) > 1e-6 {
		t.Errorf("identical vectors: sim = %f, want 1.0", sim)
	}
}

func TestCosineSimilarity_Opposite(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{-1, 0, 0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim-(-1.0)) > 1e-6 {
		t.Errorf("opposite vectors: sim = %f, want -1.0", sim)
	}
}

func TestCosineSimilarity_Orthogonal(t *testing.T) {
	a := []float32{1, 0, 0}
	b := []float32{0, 1, 0}
	sim := cosineSimilarity(a, b)
	if math.Abs(sim) > 1e-6 {
		t.Errorf("orthogonal vectors: sim = %f, want 0.0", sim)
	}
}

func TestCosineSimilarity_EmptyVectors(t *testing.T) {
	sim := cosineSimilarity(nil, nil)
	if sim != 0 {
		t.Errorf("nil vectors: sim = %f, want 0", sim)
	}
	sim = cosineSimilarity([]float32{}, []float32{})
	if sim != 0 {
		t.Errorf("empty vectors: sim = %f, want 0", sim)
	}
}

func TestCosineSimilarity_LengthMismatch(t *testing.T) {
	a := []float32{1, 2}
	b := []float32{1, 2, 3}
	sim := cosineSimilarity(a, b)
	if sim != 0 {
		t.Errorf("length mismatch: sim = %f, want 0", sim)
	}
}

func TestCosineSimilarity_ZeroVector(t *testing.T) {
	a := []float32{0, 0, 0}
	b := []float32{1, 2, 3}
	sim := cosineSimilarity(a, b)
	if sim != 0 {
		t.Errorf("zero vector: sim = %f, want 0", sim)
	}
}

func TestCosineSimilarity_KnownAngle(t *testing.T) {
	// 45-degree angle vectors
	a := []float32{1, 0}
	b := []float32{1, 1}
	sim := cosineSimilarity(a, b)
	expected := 1.0 / math.Sqrt(2) // cos(45) ≈ 0.7071
	if math.Abs(sim-expected) > 1e-4 {
		t.Errorf("45° vectors: sim = %f, want %f", sim, expected)
	}
}

// ── ruleEmbeddingThreshold ──

func TestRuleEmbeddingThreshold_Default(t *testing.T) {
	rule := Rule{JudgementLogic: JudgementLogic{}}
	th := ruleEmbeddingThreshold(rule)
	if th != 0.68 {
		t.Errorf("default threshold = %f, want 0.68", th)
	}
}

func TestRuleEmbeddingThreshold_Custom(t *testing.T) {
	rule := Rule{JudgementLogic: JudgementLogic{SimilarityThreshold: 0.85}}
	th := ruleEmbeddingThreshold(rule)
	if th != 0.85 {
		t.Errorf("custom threshold = %f, want 0.85", th)
	}
}

func TestRuleEmbeddingThreshold_InvalidZero(t *testing.T) {
	rule := Rule{JudgementLogic: JudgementLogic{SimilarityThreshold: 0}}
	th := ruleEmbeddingThreshold(rule)
	if th != 0.68 {
		t.Errorf("zero threshold should fall back to default, got %f", th)
	}
}

func TestRuleEmbeddingThreshold_InvalidOver1(t *testing.T) {
	rule := Rule{JudgementLogic: JudgementLogic{SimilarityThreshold: 1.5}}
	th := ruleEmbeddingThreshold(rule)
	if th != 0.68 {
		t.Errorf("over-1 threshold should fall back to default, got %f", th)
	}
}

func TestRuleEmbeddingThreshold_ExactlyOne(t *testing.T) {
	rule := Rule{JudgementLogic: JudgementLogic{SimilarityThreshold: 1.0}}
	th := ruleEmbeddingThreshold(rule)
	if th != 1.0 {
		t.Errorf("threshold 1.0 should be accepted, got %f", th)
	}
}

// ── buildGuidelineText ──

func TestBuildGuidelineText_FullRule(t *testing.T) {
	rule := Rule{
		CheckCategory:         "정책_시스템_설정",
		EvidenceType:          "IAM 패스워드 정책",
		System:                "AWS IAM",
		IdentificationKeywords: []string{"비밀번호", "패스워드 정책"},
		ComplianceIndicators: []Indicator{
			{Field: "MinLen", Op: ">=", Value: 10, Description: "최소 10자"},
			{Pattern: `^\$2[aby]\$`, Description: "bcrypt 해시"},
		},
		DeficiencyIndicators: []Indicator{
			{Pattern: `^[0-9a-f]{32}$`, Description: "MD5 해시"},
		},
	}
	text := buildGuidelineText(rule)
	if text == "" {
		t.Fatal("expected non-empty")
	}
	checks := []string{
		"점검항목: 정책_시스템_설정",
		"증적유형: IAM 패스워드 정책",
		"시스템: AWS IAM",
		"식별키워드: 비밀번호, 패스워드 정책",
		"준수기준: 최소 10자",
		"준수기준: bcrypt 해시",
		"결함기준: MD5 해시",
	}
	for _, c := range checks {
		if !containsSubstring(text, c) {
			t.Errorf("missing %q in guideline text:\n%s", c, text)
		}
	}
}

func TestBuildGuidelineText_MinimalRule(t *testing.T) {
	rule := Rule{CheckCategory: "변경주기_준수"}
	text := buildGuidelineText(rule)
	if !containsSubstring(text, "점검항목: 변경주기_준수") {
		t.Errorf("got: %s", text)
	}
}

func TestBuildGuidelineText_FieldBasedIndicator(t *testing.T) {
	rule := Rule{
		CheckCategory: "test",
		ComplianceIndicators: []Indicator{
			{Field: "MaxAge", Op: "<=", Value: 180},
		},
	}
	text := buildGuidelineText(rule)
	if !containsSubstring(text, "준수기준: MaxAge <= 180") {
		t.Errorf("got: %s", text)
	}
}

func containsSubstring(text, sub string) bool {
	return len(text) > 0 && len(sub) > 0 && strings.Contains(text, sub)
}
