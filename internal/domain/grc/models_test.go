package grc

import (
	"testing"
)

func TestAllowedEvidenceTypes(t *testing.T) {
	expected := []string{
		"정책_문서_존재",
		"정책_문서_충실도",
		"정책_시스템_설정",
		"사용자_화면_강제화",
		"변경주기_준수",
		"임시_비밀번호_강제_변경",
		"저장_형태",
		"인증수단",
	}
	for _, et := range expected {
		if !AllowedEvidenceTypes[et] {
			t.Errorf("expected evidence type %q to be allowed", et)
		}
	}
	if AllowedEvidenceTypes["unknown_type"] {
		t.Error("unexpected evidence type should not be allowed")
	}
}

func TestAllowedFileExtensions(t *testing.T) {
	allowed := []string{".pdf", ".png", ".jpg", ".jpeg", ".webp", ".json", ".yaml", ".yml", ".csv", ".txt"}
	for _, ext := range allowed {
		if !AllowedFileExtensions[ext] {
			t.Errorf("expected extension %q to be allowed", ext)
		}
	}
	disallowed := []string{".exe", ".zip", ".doc", ".docx", ".xls"}
	for _, ext := range disallowed {
		if AllowedFileExtensions[ext] {
			t.Errorf("expected extension %q to NOT be allowed", ext)
		}
	}
}

func TestConstants(t *testing.T) {
	if MaxFileSize != 50*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", MaxFileSize, 50*1024*1024)
	}
	if MaxTotalSize != 200*1024*1024 {
		t.Errorf("MaxTotalSize = %d, want %d", MaxTotalSize, 200*1024*1024)
	}
	if MaxFileCount != 50 {
		t.Errorf("MaxFileCount = %d, want 50", MaxFileCount)
	}
}

func TestCheckDefaults(t *testing.T) {
	chk := Check{
		Status:      "queued",
		ProgressPct: 0,
	}
	if chk.Status != "queued" {
		t.Errorf("check.Status = %q, want queued", chk.Status)
	}
	if chk.ProgressPct != 0 {
		t.Errorf("check.ProgressPct = %d, want 0", chk.ProgressPct)
	}
}

func TestViolationSeverity(t *testing.T) {
	v := Violation{
		Field:       "MinimumPasswordLength",
		Expected:    ">= 10",
		Actual:      8,
		Description: "최소 길이 8자로 설정되어 있어 법령 기준 10자 미달",
		Severity:    "high",
	}
	if v.Severity != "high" {
		t.Errorf("violation severity = %q, want high", v.Severity)
	}
}

func TestSummaryAggregation(t *testing.T) {
	s := Summary{
		TotalRules:        15,
		Passed:            12,
		Failed:            3,
		Skipped:           0,
		EvidenceCollected: 15,
	}
	if s.Passed+s.Failed+s.Skipped != s.TotalRules {
		t.Errorf("passed(%d)+failed(%d)+skipped(%d) != total(%d)", s.Passed, s.Failed, s.Skipped, s.TotalRules)
	}
}
