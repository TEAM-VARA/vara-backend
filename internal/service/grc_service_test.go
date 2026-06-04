package service

import (
	"os"
	"strings"
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

// ─────────────────────────────────────────────
// GenerateJobID
// ─────────────────────────────────────────────

func TestGenerateJobID(t *testing.T) {
	id := GenerateJobID()
	if len(id) != 13 { // "ck_" + 10 chars
		t.Errorf("job id length = %d, want 13: %q", len(id), id)
	}
	if id[:3] != "ck_" {
		t.Errorf("job id prefix = %q, want ck_", id[:3])
	}

	// Ensure uniqueness.
	id2 := GenerateJobID()
	if id == id2 {
		t.Error("two consecutive job IDs should not be identical")
	}
}

// ─────────────────────────────────────────────
// compareValues
// ─────────────────────────────────────────────

func TestCompareValues_Numeric(t *testing.T) {
	tests := []struct {
		actual   any
		op       string
		expected any
		want     bool
	}{
		{10.0, ">=", 10, true},
		{8.0, ">=", 10, false},
		{180, "<=", 180, true},
		{200, "<=", 180, false},
		{true, "==", true, true},
		{false, "==", true, false},
		{0, "!=", 0, false},
		{5, ">", 3, true},
		{3, "<", 5, true},
		{"Enabled", "==", "Enabled", true},
		{"Disabled", "==", "Enabled", false},
		{"STRONG", "!=", "LOW", true},
	}

	for _, tt := range tests {
		got := compareValues(tt.actual, tt.op, tt.expected)
		if got != tt.want {
			t.Errorf("compareValues(%v, %q, %v) = %v, want %v", tt.actual, tt.op, tt.expected, got, tt.want)
		}
	}
}

// ─────────────────────────────────────────────
// evaluateStructured
// ─────────────────────────────────────────────

func TestEvaluateStructured_Compliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R005",
		ComplianceIndicators: []Indicator{
			{Field: "MinimumPasswordLength", Op: ">=", Value: float64(10)},
			{Field: "RequireSymbols", Op: "==", Value: true},
			{Field: "MaxPasswordAge", Op: "<=", Value: float64(180)},
		},
		JudgmentLogic: JudgmentLogic{Type: "structured_match"},
	}

	evidenceData := []any{
		map[string]any{
			"MinimumPasswordLength": float64(12),
			"RequireSymbols":        true,
			"MaxPasswordAge":        float64(90),
		},
	}

	base := grc.RuleResult{
		RuleID:        rule.RuleID,
		EvidenceFiles: []string{"iam_policy.json"},
	}

	result := evaluateStructured(rule, evidenceData, base)
	if result.Verdict != "준수" {
		t.Errorf("verdict = %q, want 준수", result.Verdict)
	}
	if len(result.MatchedIndicators) != 3 {
		t.Errorf("matched indicators count = %d, want 3", len(result.MatchedIndicators))
	}
}

func TestEvaluateStructured_NonCompliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R005",
		ComplianceIndicators: []Indicator{
			{Field: "MinimumPasswordLength", Op: ">=", Value: float64(10), Description: "최소 길이 10자 이상"},
			{Field: "RequireSymbols", Op: "==", Value: true, Description: "특수문자 강제"},
		},
		JudgmentLogic: JudgmentLogic{Type: "structured_match"},
	}

	evidenceData := []any{
		map[string]any{
			"MinimumPasswordLength": float64(8),
			"RequireSymbols":        false,
		},
	}

	base := grc.RuleResult{
		RuleID:        rule.RuleID,
		EvidenceFiles: []string{"iam_policy.json"},
	}

	result := evaluateStructured(rule, evidenceData, base)
	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수", result.Verdict)
	}
	if len(result.Violations) != 2 {
		t.Errorf("violations count = %d, want 2", len(result.Violations))
	}

	// Check violation details.
	for _, v := range result.Violations {
		if v.Severity != "high" {
			t.Errorf("violation severity = %q, want high", v.Severity)
		}
	}
}

func TestEvaluateStructured_MissingField(t *testing.T) {
	rule := Rule{
		RuleID: "test-rule",
		ComplianceIndicators: []Indicator{
			{Field: "SomeField", Op: ">=", Value: float64(10)},
		},
		JudgmentLogic: JudgmentLogic{Type: "structured_match"},
	}

	evidenceData := []any{
		map[string]any{
			"OtherField": float64(20),
		},
	}

	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"test.json"}}
	result := evaluateStructured(rule, evidenceData, base)
	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수 for missing field", result.Verdict)
	}
}

// ─────────────────────────────────────────────
// evaluateKeywordMatch (semantic_match)
// ─────────────────────────────────────────────

func TestEvaluateKeywordMatch_Compliant(t *testing.T) {
	rule := Rule{
		RuleID:                 "2.5.4-R001",
		Keywords: []string{"비밀번호 관리", "패스워드 정책", "계정 관리", "사용자 인증"},
		JudgmentLogic:         JudgmentLogic{Type: "semantic_match", MinKeywordMatches: 2},
	}

	text := "본 문서는 비밀번호 관리 절차를 규정한다. 사용자 인증 및 패스워드 정책을 포함한다."
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"policy.pdf"}}

	result := evaluateKeywordMatch(rule, text, base)
	if result.Verdict != "준수" {
		t.Errorf("verdict = %q, want 준수", result.Verdict)
	}
}

func TestEvaluateKeywordMatch_NonCompliant(t *testing.T) {
	rule := Rule{
		RuleID:                 "2.5.4-R001",
		Keywords: []string{"비밀번호 관리", "패스워드 정책", "계정 관리", "사용자 인증"},
		JudgmentLogic:         JudgmentLogic{Type: "semantic_match", MinKeywordMatches: 2},
	}

	text := "이 문서는 일반적인 IT 운영 절차를 설명합니다."
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"policy.pdf"}}

	result := evaluateKeywordMatch(rule, text, base)
	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수", result.Verdict)
	}
}

// ─────────────────────────────────────────────
// evaluateElementCoverage
// ─────────────────────────────────────────────

func TestEvaluateElementCoverage_AllPresent(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R002",
		RequiredContentElements: map[string][]ContentElement{
			"writing_rules": {
				{ID: "WR-01", Description: "길이·복잡도", MatchKeywords: []string{"10자리", "8자리", "복잡도"}},
				{ID: "WR-02", Description: "추측 쉬운 비밀번호", MatchKeywords: []string{"생일", "전화번호", "추측"}},
			},
		},
		JudgmentLogic: JudgmentLogic{Type: "semantic_match", Method: "element_coverage_check"},
	}

	text := "비밀번호는 10자리 이상이어야 하며, 복잡도 요구사항을 충족해야 합니다. 생일이나 전화번호 등 추측 가능한 비밀번호는 금지합니다."
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"policy.pdf"}}

	result := evaluateElementCoverage(rule, text, base)
	if result.Verdict != "준수" {
		t.Errorf("verdict = %q, want 준수", result.Verdict)
	}
}

func TestEvaluateElementCoverage_Missing(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R002",
		RequiredContentElements: map[string][]ContentElement{
			"writing_rules": {
				{ID: "WR-01", Description: "길이·복잡도", MatchKeywords: []string{"10자리", "8자리", "복잡도"}},
				{ID: "WR-02", Description: "추측 쉬운 비밀번호", MatchKeywords: []string{"생일", "전화번호", "추측"}},
			},
		},
		JudgmentLogic: JudgmentLogic{Type: "semantic_match", Method: "element_coverage_check"},
	}

	text := "비밀번호는 10자리 이상이어야 합니다."
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"policy.pdf"}}

	result := evaluateElementCoverage(rule, text, base)
	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수", result.Verdict)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations for missing elements")
	}
}

// ─────────────────────────────────────────────
// evaluateRegex
// ─────────────────────────────────────────────

func TestEvaluateRegex_BcryptCompliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R013",
		ComplianceIndicators: []Indicator{
			{Pattern: `^\$2[aby]\$`, Type: "regex", Description: "bcrypt"},
			{Pattern: `^\$argon2(i|id)\$`, Type: "regex", Description: "argon2"},
		},
		JudgmentLogic: JudgmentLogic{Type: "regex_match"},
	}

	evidenceData := []any{
		"$2b$12$LJ3m4ys3Lk0TDbGMOgHFK.RYsEnJFnJN8qQaJzsnUfITUqBWXl5bC\n$2b$12$aBcDefGhIjKlMnOpQrStUvWxYz012345678901234567890",
	}

	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"password_hashes.txt"}}
	result := evaluateRegex(rule, evidenceData, base)
	if result.Verdict != "준수" {
		t.Errorf("verdict = %q, want 준수 for bcrypt hashes", result.Verdict)
	}
}

func TestEvaluateRegex_MD5NonCompliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R013",
		ComplianceIndicators: []Indicator{
			{Pattern: `^\$2[aby]\$`, Type: "regex", Description: "bcrypt"},
		},
		JudgmentLogic: JudgmentLogic{Type: "regex_match"},
	}

	evidenceData := []any{
		"5d41402abc4b2a76b9719d911017c592",
	}

	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"password_hashes.txt"}}
	result := evaluateRegex(rule, evidenceData, base)
	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수 for MD5 hash", result.Verdict)
	}
}

// ─────────────────────────────────────────────
// evaluateAggregated
// ─────────────────────────────────────────────

func TestEvaluateAggregated_Compliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R009",
		ComplianceIndicators: []Indicator{
			{Field: "days_since_change", Op: ">", Value: float64(180)},
		},
		JudgmentLogic: JudgmentLogic{
			Type:                  "aggregated_statistics",
			ViolationThresholdPct: 5,
		},
	}

	// 20 accounts, all within 180 days.
	var records []map[string]string
	for i := 0; i < 20; i++ {
		records = append(records, map[string]string{
			"days_since_change": "30",
		})
	}

	evidenceData := []any{records}
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"accounts.csv"}}
	result := evaluateAggregated(rule, evidenceData, base)

	if result.Verdict != "준수" {
		t.Errorf("verdict = %q, want 준수", result.Verdict)
	}
}

func TestEvaluateAggregated_NonCompliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R009",
		ComplianceIndicators: []Indicator{
			{Field: "days_since_change", Op: ">", Value: float64(180)},
		},
		JudgmentLogic: JudgmentLogic{
			Type:                  "aggregated_statistics",
			ViolationThresholdPct: 5,
		},
	}

	// 20 accounts, 3 over 180 days (15% > 5% threshold).
	var records []map[string]string
	for i := 0; i < 17; i++ {
		records = append(records, map[string]string{"days_since_change": "30"})
	}
	for i := 0; i < 3; i++ {
		records = append(records, map[string]string{"days_since_change": "200"})
	}

	evidenceData := []any{records}
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"accounts.csv"}}
	result := evaluateAggregated(rule, evidenceData, base)

	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수", result.Verdict)
	}
}

// ─────────────────────────────────────────────
// evaluateCodePattern
// ─────────────────────────────────────────────

func TestEvaluateCodePattern_Compliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R010",
		Keywords: []string{
			"isTemporary", "temp_password", "must_change_password",
			"forceChangePassword", "redirect('/change-password')",
		},
		JudgmentLogic: JudgmentLogic{Type: "code_pattern_match", MinPatterns: 2},
	}

	code := `
func login(user User) {
	if user.isTemporary {
		redirect('/change-password')
	}
	if user.must_change_password {
		forceChangePassword(user)
	}
}
`
	evidenceData := []any{code}
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"auth.go"}}
	result := evaluateCodePattern(rule, evidenceData, base)

	if result.Verdict != "준수" {
		t.Errorf("verdict = %q, want 준수", result.Verdict)
	}
}

func TestEvaluateCodePattern_NonCompliant(t *testing.T) {
	rule := Rule{
		RuleID: "2.5.4-R010",
		Keywords: []string{
			"isTemporary", "temp_password", "must_change_password",
			"forceChangePassword", "redirect('/change-password')",
		},
		JudgmentLogic: JudgmentLogic{Type: "code_pattern_match", MinPatterns: 2},
	}

	code := `
func login(user User) {
	// normal login
	createSession(user)
}
`
	evidenceData := []any{code}
	base := grc.RuleResult{RuleID: rule.RuleID, EvidenceFiles: []string{"auth.go"}}
	result := evaluateCodePattern(rule, evidenceData, base)

	if result.Verdict != "미준수" {
		t.Errorf("verdict = %q, want 미준수", result.Verdict)
	}
}

// ─────────────────────────────────────────────
// matchEvidenceToRule
// ─────────────────────────────────────────────

func TestMatchEvidenceToRule_ByCategory(t *testing.T) {
	files := []grc.EvidenceFile{
		{Filename: "policy.pdf", EvidenceType: "정책_문서_존재"},
		{Filename: "iam.json", EvidenceType: "정책_시스템_설정"},
		{Filename: "accounts.csv", EvidenceType: "변경주기_준수"},
	}

	rule := Rule{RuleID: "2.5.4-R005"}
	matched := matchEvidenceToRule(files, rule, nil)

	if len(matched) != 1 {
		t.Fatalf("matched count = %d, want 1", len(matched))
	}
	if matched[0].Filename != "iam.json" {
		t.Errorf("matched file = %q, want iam.json", matched[0].Filename)
	}
}

func TestMatchEvidenceToRule_ByTargetRuleIDs(t *testing.T) {
	files := []grc.EvidenceFile{
		{Filename: "screenshot.png", EvidenceType: "정책_시스템_설정", TargetRuleIDs: []string{"2.5.4-R003"}},
		{Filename: "iam.json", EvidenceType: "정책_시스템_설정", TargetRuleIDs: []string{"2.5.4-R005"}},
	}

	rule := Rule{RuleID: "2.5.4-R005"}
	matched := matchEvidenceToRule(files, rule, nil)

	if len(matched) != 1 {
		t.Fatalf("matched count = %d, want 1", len(matched))
	}
	if matched[0].Filename != "iam.json" {
		t.Errorf("matched file = %q, want iam.json", matched[0].Filename)
	}
}

func TestMatchEvidenceToRule_NoMatch(t *testing.T) {
	files := []grc.EvidenceFile{
		{Filename: "policy.pdf", EvidenceType: "정책_문서_존재"},
	}

	rule := Rule{RuleID: "2.5.4-R009"}
	matched := matchEvidenceToRule(files, rule, nil)

	if len(matched) != 0 {
		t.Errorf("matched count = %d, want 0", len(matched))
	}
}

// ─────────────────────────────────────────────
// aggregateSummary
// ─────────────────────────────────────────────

func TestAggregateSummary(t *testing.T) {
	results := []grc.RuleResult{
		{Verdict: "준수"},
		{Verdict: "준수"},
		{Verdict: "미준수"},
		{Verdict: "skipped"},
		{Verdict: "준수"},
	}

	summary := aggregateSummary(results, 4)
	if summary.TotalRules != 5 {
		t.Errorf("total = %d, want 5", summary.TotalRules)
	}
	if summary.Passed != 3 {
		t.Errorf("passed = %d, want 3", summary.Passed)
	}
	if summary.Failed != 1 {
		t.Errorf("failed = %d, want 1", summary.Failed)
	}
	if summary.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", summary.Skipped)
	}
	if summary.EvidenceCollected != 4 {
		t.Errorf("evidence_collected = %d, want 4", summary.EvidenceCollected)
	}
}

// ─────────────────────────────────────────────
// generateRecommendations
// ─────────────────────────────────────────────

func TestGenerateRecommendations(t *testing.T) {
	results := []grc.RuleResult{
		{RuleID: "2.5.4-R001", Verdict: "준수"},
		{RuleID: "2.5.4-R005", Verdict: "미준수", Violations: []grc.Violation{
			{Description: "MinimumPasswordLength 미달", Severity: "high"},
		}},
		{RuleID: "2.5.4-R009", Verdict: "skipped", SkipReason: "증적 미제출"},
	}

	ruleset := &Ruleset{
		Rules: []Rule{
			{RuleID: "2.5.4-R001"},
			{RuleID: "2.5.4-R005"},
			{RuleID: "2.5.4-R009"},
		},
		LegalRefs: []LegalReference{
			{Law: "개인정보의 안전성 확보조치 기준", Article: "제5조제5항"},
		},
	}

	recs := generateRecommendations(results, ruleset)
	if len(recs) != 1 { // Only 미준수 get recommendations.
		t.Fatalf("recommendations count = %d, want 1", len(recs))
	}
	if recs[0].RuleID != "2.5.4-R005" {
		t.Errorf("recommendation rule_id = %q, want 2.5.4-R005", recs[0].RuleID)
	}
	if recs[0].Action == "" {
		t.Error("recommendation action should not be empty")
	}
	if recs[0].Reference == "" {
		t.Error("recommendation reference should not be empty")
	}
}

func TestGenerateRecommendations_K8sSourcePrefix(t *testing.T) {
	results := []grc.RuleResult{
		{
			RuleID: "2.5.4-R005", Verdict: "미준수",
			Violations: []grc.Violation{{Description: "MinimumPasswordLength 미달", Severity: "high"}},
			EvidenceSources: []grc.EvidenceAttribution{{
				Filename: "svc.yaml",
				K8sSource: grc.K8sSource{
					ClusterName: "c1", Namespace: "ns1", ResourceKind: "Service", ResourceName: "api",
				},
			}},
		},
	}
	ruleset := &Ruleset{
		Rules:     []Rule{{RuleID: "2.5.4-R005"}},
		LegalRefs: []LegalReference{{Law: "개인정보의 안전성 확보조치 기준", Article: "제5조제5항"}},
	}
	recs := generateRecommendations(results, ruleset)
	if len(recs) != 1 {
		t.Fatalf("count = %d", len(recs))
	}
	if !strings.Contains(recs[0].Action, "Kubernetes") || !strings.Contains(recs[0].Action, "Service/api") {
		t.Fatalf("action should cite K8s source, got: %s", recs[0].Action)
	}
}

// ─────────────────────────────────────────────
// GRCError
// ─────────────────────────────────────────────

func TestGRCError(t *testing.T) {
	err := &GRCError{Code: "INVALID_REQUEST", Message: "test error", HTTPStatus: 400}
	if err.Error() != "[INVALID_REQUEST] test error" {
		t.Errorf("error string = %q", err.Error())
	}
}

// ─────────────────────────────────────────────
// toFloat64
// ─────────────────────────────────────────────

func TestToFloat64(t *testing.T) {
	tests := []struct {
		input    any
		expected float64
		ok       bool
	}{
		{float64(42), 42, true},
		{float32(3.14), 3.140000104904175, true},
		{int(10), 10, true},
		{int64(100), 100, true},
		{"123.45", 123.45, true},
		{true, 1, true},
		{false, 0, true},
		{nil, 0, false},
		{[]int{1}, 0, false},
	}

	for _, tt := range tests {
		got, ok := toFloat64(tt.input)
		if ok != tt.ok {
			t.Errorf("toFloat64(%v): ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.expected {
			t.Errorf("toFloat64(%v) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

// ─────────────────────────────────────────────
// CSV parsing
// ─────────────────────────────────────────────

func TestParseCSVFile(t *testing.T) {
	// Create a temporary CSV file.
	tmpDir := t.TempDir()
	csvPath := tmpDir + "/test.csv"
	content := "User ID,days_since_change,Status\nuser1,30,Active\nuser2,200,Active\nuser3,10,Active\n"

	if err := writeTestFile(csvPath, content); err != nil {
		t.Fatalf("failed to write test CSV: %v", err)
	}

	rows, err := parseCSVFile(csvPath)
	if err != nil {
		t.Fatalf("parseCSVFile failed: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0]["User ID"] != "user1" {
		t.Errorf("row[0][User ID] = %q, want user1", rows[0]["User ID"])
	}
	if rows[1]["days_since_change"] != "200" {
		t.Errorf("row[1][days_since_change] = %q, want 200", rows[1]["days_since_change"])
	}
}

func TestParseJSONFile(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := tmpDir + "/test.json"
	content := `{"MinimumPasswordLength": 12, "RequireSymbols": true}`

	if err := writeTestFile(jsonPath, content); err != nil {
		t.Fatalf("failed to write test JSON: %v", err)
	}

	data, err := parseJSONFile(jsonPath)
	if err != nil {
		t.Fatalf("parseJSONFile failed: %v", err)
	}

	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", data)
	}
	if m["MinimumPasswordLength"] != float64(12) {
		t.Errorf("MinimumPasswordLength = %v, want 12", m["MinimumPasswordLength"])
	}
}

func TestReadTextFile(t *testing.T) {
	tmpDir := t.TempDir()
	txtPath := tmpDir + "/test.txt"
	content := "hello world\nsecond line"

	if err := writeTestFile(txtPath, content); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	text, err := readTextFile(txtPath)
	if err != nil {
		t.Fatalf("readTextFile failed: %v", err)
	}
	if text != content {
		t.Errorf("text = %q, want %q", text, content)
	}
}

// writeTestFile is a helper to create test files.
func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
