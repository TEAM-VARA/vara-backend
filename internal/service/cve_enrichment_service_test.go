package service

import (
	"testing"

	"github.com/vara/backend/internal/domain/scoring"
)

// §13-2: 소스에 substring으로 없는 module/function/mechanism은 강제 null.
func TestApplyExtraction_SubstringFloor(t *testing.T) {
	source := `Apache Tomcat Default Servlet partial PUT writes a temporary file that is later
	deserialized via file based session persistence. Fixed in 9.0.99 and 10.1.35.`

	fn := "exploitDeserialize" // 소스에 없음 → 환각, null이어야 함
	cand := &extractCandidate{
		Module:      "Apache Tomcat Default Servlet", // 소스에 있음 → 채택
		ModuleShort: "Tomcat Default Servlet",        // "Tomcat Default Servlet"는 소스에 substring으로 없음(중간에 'partial PUT' 없음? 실제로는 없음)
		Function:    fn,                              // 소스에 없음 → null
		Mechanism:   "partial PUT으로 파일을 심고 역직렬화 유발",
		MechanismShort: "partial PUT → 역직렬화",
		MechanismSpans: []scoring.MechanismSpan{
			{Text: "partial PUT", Src: "advisory"},                  // 있음
			{Text: "file based session persistence", Src: "advisory"}, // 있음
			{Text: "totally made up gadget chain", Src: "advisory"},  // 없음 → 제거
		},
		FixedVersions: []string{"9.0.99", "10.1.35", "99.99.99"}, // 마지막은 소스에 없음 → 제거
		Preconditions: []scoring.Precondition{{ID: "default_servlet_write", Text: "write enabled"}},
	}

	e := &scoring.CVEEnrichment{CVEID: "CVE-TEST", Provenance: map[string]string{}}
	applyExtraction(e, cand, source)

	if e.Module != "Apache Tomcat Default Servlet" {
		t.Errorf("module in source must be kept, got %q", e.Module)
	}
	if e.Function != nil {
		t.Errorf("function not in source must be null, got %q", *e.Function)
	}
	if len(e.MechanismSpans) != 2 {
		t.Errorf("only spans present in source must survive, got %d: %+v", len(e.MechanismSpans), e.MechanismSpans)
	}
	if e.Mechanism == "" {
		t.Error("mechanism must be kept when >=1 span survives")
	}
	if len(e.FixedVersions) != 2 {
		t.Errorf("hallucinated version must be dropped, got %v", e.FixedVersions)
	}
	if len(e.Preconditions) != 1 || e.Preconditions[0].Provenance != "advisory" {
		t.Errorf("preconditions kept with advisory provenance when spans survive, got %+v", e.Preconditions)
	}
}

// §13-1: advisory에 메커니즘 근거(span)가 전혀 없으면 mechanism 전체가 null.
func TestApplyExtraction_NoValidSpans_NullsMechanism(t *testing.T) {
	source := "Some unrelated advisory text with no matching spans."
	cand := &extractCandidate{
		Mechanism:      "fabricated mechanism",
		MechanismShort: "fabricated",
		MechanismSpans: []scoring.MechanismSpan{{Text: "not in source at all", Src: "advisory"}},
		Preconditions:  []scoring.Precondition{{ID: "x"}},
	}
	e := &scoring.CVEEnrichment{CVEID: "CVE-TEST", Provenance: map[string]string{}}
	applyExtraction(e, cand, source)

	if e.Mechanism != "" || len(e.MechanismSpans) != 0 {
		t.Errorf("no surviving span → mechanism must be null, got %q / %+v", e.Mechanism, e.MechanismSpans)
	}
	if len(e.Preconditions) != 0 {
		t.Errorf("no advisory basis → preconditions dropped, got %+v", e.Preconditions)
	}
	if e.Provenance["mechanism"] != "not_specified_in_source" {
		t.Errorf("provenance must record not_specified_in_source, got %q", e.Provenance["mechanism"])
	}
}

func TestExtractJSONObject(t *testing.T) {
	raw := "어쩌고 설명...\n{\"module\":\"x\",\"nested\":{\"a\":1}}\n뒤에 붙은 산문"
	got := extractJSONObject(raw)
	want := `{"module":"x","nested":{"a":1}}`
	if got != want {
		t.Errorf("extractJSONObject nested = %q, want %q", got, want)
	}
	if extractJSONObject("no json here") != "" {
		t.Error("no-brace input must return empty")
	}
}
