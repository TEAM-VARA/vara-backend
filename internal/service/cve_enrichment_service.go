package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/platform/advisory"
	"github.com/vara/backend/internal/platform/nvd"
	"github.com/vara/backend/internal/platform/vlm"
	"github.com/vara/backend/internal/repository/postgres"
)

// CVEEnrichmentService — CVE 단위 narrative enrichment(설계서 §4)를 생성·캐시한다 (L1).
//
// 흐름(설계서 §3.2): NVD(desc/CWE/references) + KEV/EPSS(global) → advisory fetch
// → LLM 추출(서술 4필드) → 검증(substring floor + CVSS 우선) → attack/mitigations 도출 → 캐시.
//
// config-free(L1 불변식): 클러스터 상태를 입력받지 않는다. pod별 충족 판정(L2)은 별도 기능.
type CVEEnrichmentService struct {
	enrichRepo *postgres.CVEEnrichmentRepo
	globalRepo *postgres.GlobalScoringRepo // KEV/EPSS/PoC 신호 (signals 채움)
	nvd        *nvd.Client
	advisory   *advisory.Client
	vlm        *vlm.Client

	inflight sync.Map // cveID -> struct{} : 동시 추출 중복 방지(singleflight 경량 대체)
}

// NewCVEEnrichmentService — 의존성 주입. 어느 하나라도 nil이면 그 단계는 graceful skip.
func NewCVEEnrichmentService(
	er *postgres.CVEEnrichmentRepo,
	gr *postgres.GlobalScoringRepo,
	n *nvd.Client,
	adv *advisory.Client,
	v *vlm.Client,
) *CVEEnrichmentService {
	return &CVEEnrichmentService{enrichRepo: er, globalRepo: gr, nvd: n, advisory: adv, vlm: v}
}

const (
	maxAdvisoryRefs   = 3
	enrichMaxTokens   = 4096
	enrichBgTimeout   = 90 * time.Second
)

// GetOrEnrich — 캐시된 enrichment를 반환한다. 없거나 만료면 nil을 즉시 반환하고
// 백그라운드로 추출을 트리거한다(비차단). 첫 호출은 generic, 캐시 후 다음 호출부터 enriched.
func (s *CVEEnrichmentService) GetOrEnrich(ctx context.Context, cveID string) (*scoring.CVEEnrichment, error) {
	if s == nil || s.enrichRepo == nil || !strings.HasPrefix(cveID, "CVE-") {
		return nil, nil
	}
	if e, err := s.enrichRepo.GetFresh(ctx, cveID); err == nil && e != nil {
		return e, nil
	}
	s.triggerEnrich(cveID)
	return nil, nil
}

// triggerEnrich — cveID당 1개의 백그라운드 추출만 실행(inflight 가드).
func (s *CVEEnrichmentService) triggerEnrich(cveID string) {
	if _, busy := s.inflight.LoadOrStore(cveID, struct{}{}); busy {
		return
	}
	go func() {
		defer s.inflight.Delete(cveID)
		ctx, cancel := context.WithTimeout(context.Background(), enrichBgTimeout)
		defer cancel()
		if err := s.enrich(ctx, cveID); err != nil {
			log.Printf("[cve-enrich] %s: %v", cveID, err)
		}
	}()
}

// enrich — 단일 CVE를 추출해 캐시한다. 동기. triggerEnrich가 백그라운드에서 호출.
func (s *CVEEnrichmentService) enrich(ctx context.Context, cveID string) error {
	// ── 1) 구조화 신호: GlobalScore(CVSS 벡터·KEV·EPSS·PoC) ──
	var (
		cvssVector string
		cvssScore  float64
		inKEV      bool
		inPoC      bool
		epssPtr    *float64
	)
	if s.globalRepo != nil {
		if g, err := s.globalRepo.GetByCVEID(ctx, cveID); err == nil && g != nil {
			cvssVector = g.CVSSVector
			cvssScore = g.CVSSScore
			inKEV = g.InKEV
			inPoC = g.InExploitDB
			if g.EPSSFound {
				v := g.EPSSScore
				epssPtr = &v
			}
		}
	}

	// ── 2) NVD: description / CWE / references (CVSS 벡터 보강) ──
	var (
		description string
		cwes        []string
		refs        []nvd.Reference
	)
	if s.nvd != nil {
		if info, err := s.nvd.FetchCVE(ctx, cveID); err == nil && info != nil && info.Found {
			description = info.Description
			cwes = info.CWEs
			refs = info.References
			if cvssVector == "" {
				cvssVector = info.VectorString
			}
			if cvssScore == 0 {
				cvssScore = info.CVSSScore
			}
		}
	}

	// ── 3) advisory fetch (allowlist, 상위 N개) → source 본문 ──
	advisoryText := s.fetchAdvisories(ctx, refs)
	sourceText := strings.TrimSpace(description + "\n\n" + advisoryText)
	sourceHash := hashSource(sourceText, cvssVector)

	// ── CVSS 우선(설계서 §5.3): impact/remote/unauth는 벡터 파싱이 결정 ──
	remote, availability, confidentiality, scopeChanged, unauth := scoring.ParseCVSSFlags(cvssVector)
	impact := scoring.DeriveImpact(cwes, availability, confidentiality)

	e := &scoring.CVEEnrichment{
		CVEID:      cveID,
		VulnClass:  cwes,
		Impact:     impact,
		Remote:     remote,
		Unauth:     unauth,
		Confidence: scoring.ConfidenceUnconfirmed,
		Validated:  false,
		Provenance: map[string]string{
			"attack":      "derived_from_cvss_cwe",
			"mitigations": "derived",
			"function":    "not_specified_in_source",
		},
		CVSS:    buildCVSSInfo(cvssVector, cvssScore, scopeChanged),
		Signals: buildSignals(inKEV, inPoC, epssPtr),
	}

	// ── 4) LLM 추출(서술 필드) — vlm 가동 + source 있을 때만. 없으면 구조화 신호만. ──
	if s.vlm != nil && s.vlm.Available() && sourceText != "" {
		if cand, err := s.extract(ctx, cveID, cwes, cvssVector, description, advisoryText); err == nil && cand != nil {
			applyExtraction(e, cand, sourceText)
		} else if err != nil {
			log.Printf("[cve-enrich] %s extract: %v", cveID, err)
		}
	}

	// ── 5) 도출: attack / mitigations (CVSS·CWE·precondition 기반) ──
	e.Attack = scoring.DeriveAttack(e.Impact, e.Remote, e.Unauth)
	e.Mitigations = scoring.DeriveMitigations(e.FixedVersions, e.Preconditions)

	// ── 6) 캐시 ──
	return s.enrichRepo.Upsert(ctx, e, sourceHash)
}

// fetchAdvisories — allowlist 통과 + 우선순위 태그 ref를 상위 N개만 fetch해 본문을 합친다.
func (s *CVEEnrichmentService) fetchAdvisories(ctx context.Context, refs []nvd.Reference) string {
	if s.advisory == nil {
		return ""
	}
	ordered := prioritizeRefs(refs)
	var b strings.Builder
	n := 0
	for _, url := range ordered {
		if n >= maxAdvisoryRefs {
			break
		}
		text, err := s.advisory.FetchText(ctx, url)
		if err != nil || text == "" {
			continue
		}
		b.WriteString("\n\n=== ")
		b.WriteString(url)
		b.WriteString(" ===\n")
		b.WriteString(text)
		n++
	}
	return b.String()
}

// prioritizeRefs — allowlist URL만 추려 "Vendor Advisory/Patch/Exploit/Mitigation" 태그를 앞으로.
func prioritizeRefs(refs []nvd.Reference) []string {
	var tagged, untagged []string
	preferred := map[string]bool{
		"Vendor Advisory": true, "Patch": true, "Exploit": true,
		"Mitigation": true, "Release Notes": true, "Third Party Advisory": true,
	}
	seen := map[string]bool{}
	for _, r := range refs {
		if seen[r.URL] || !advisory.IsAllowedURL(r.URL) {
			continue
		}
		seen[r.URL] = true
		isPref := false
		for _, t := range r.Tags {
			if preferred[t] {
				isPref = true
				break
			}
		}
		if isPref {
			tagged = append(tagged, r.URL)
		} else {
			untagged = append(untagged, r.URL)
		}
	}
	return append(tagged, untagged...)
}

// extractCandidate — LLM이 추출하는 서술 필드(검증 전 후보).
type extractCandidate struct {
	Module              string                  `json:"module"`
	ModuleShort         string                  `json:"module_short"`
	Function            string                  `json:"function"`
	Mechanism           string                  `json:"mechanism"`
	MechanismShort      string                  `json:"mechanism_short"`
	MechanismSpans      []scoring.MechanismSpan `json:"mechanism_spans"`
	Preconditions       []scoring.Precondition  `json:"preconditions"`
	FixedVersions       []string                `json:"fixed_versions"`
	VulnClassLabel      string                  `json:"vuln_class_label"`
	VulnClassLabelShort string                  `json:"vuln_class_label_short"`
}

const enrichSystemPrompt = `너는 보안 권고문(advisory)에서 사실만 추출하는 추출기다. 설명을 생성(generate)하지 말고, 제공된 텍스트에 근거가 있는 것만 추출한다.

엄격 규칙(반드시 준수):
1. module/function/mechanism/preconditions는 제공된 텍스트에 근거가 있을 때만 채운다.
2. 근거가 없으면 추측하지 말고 null(또는 빈 배열)로 둔다. 특히 function(메서드/심볼명)은 텍스트에 명시된 경우에만.
3. mechanism은 텍스트의 연속 구절(span)을 인용해 mechanism_spans에 함께 제시한다. 각 span의 text는 원문에 그대로 존재해야 한다.
4. 익스플로잇 명령/페이로드(예: 정확한 payload, ysoserial 명령 등)는 절대 출력하지 않는다. 방어자 관점의 메커니즘·전제·완화책까지만.
5. CVSS/영향(RCE/원격/인증)은 추출하지 않는다(별도 계산). 컴포넌트·메커니즘·전제·패치버전·취약점클래스 라벨만.
6. 반드시 JSON 객체 하나만 출력. 산문/마크다운/코드펜스 금지.

출력 스키마:
{"module":string|null,"module_short":string|null,"function":string|null,"mechanism":string|null,"mechanism_short":string|null,"mechanism_spans":[{"text":string,"src":string}],"preconditions":[{"id":string,"text":string,"default_state":"disabled|enabled|conditional","exploit_when":string,"negation":string,"check_signal":string}],"fixed_versions":[string],"vuln_class_label":string|null,"vuln_class_label_short":string|null}`

// extract — advisory 텍스트에서 서술 필드를 LLM으로 추출한다(검증 전 후보).
func (s *CVEEnrichmentService) extract(ctx context.Context, cveID string, cwes []string, vector, description, advisoryText string) (*extractCandidate, error) {
	var u strings.Builder
	fmt.Fprintf(&u, "## CVE\n%s\n\n", cveID)
	if len(cwes) > 0 {
		fmt.Fprintf(&u, "## CWE\n%s\n\n", strings.Join(cwes, ", "))
	}
	if vector != "" {
		fmt.Fprintf(&u, "## CVSS 벡터(참고용, 추출 대상 아님)\n%s\n\n", vector)
	}
	if description != "" {
		fmt.Fprintf(&u, "## NVD 설명\n%s\n\n", description)
	}
	if advisoryText != "" {
		fmt.Fprintf(&u, "## 권고문 본문\n%s\n", advisoryText)
	}
	u.WriteString("\n위 텍스트에 근거가 있는 것만 추출해 JSON으로만 출력하라.")

	raw, err := s.vlm.CompleteMax(ctx, enrichSystemPrompt, u.String(), 0.0, enrichMaxTokens)
	if err != nil {
		return nil, err
	}
	jsonStr := extractJSONObject(raw)
	if jsonStr == "" {
		return nil, fmt.Errorf("no JSON object in LLM output")
	}
	var cand extractCandidate
	if err := json.Unmarshal([]byte(jsonStr), &cand); err != nil {
		return nil, fmt.Errorf("unmarshal candidate: %w", err)
	}
	return &cand, nil
}

// applyExtraction — 후보에 substring floor 검증을 적용해 enrichment에 반영(설계서 §5.3).
// 소스에 substring으로 존재하지 않는 module/function/mechanism은 강제 null(환각 차단).
func applyExtraction(e *scoring.CVEEnrichment, c *extractCandidate, source string) {
	src := strings.ToLower(source)

	// module: full 또는 short 중 하나라도 소스에 있으면 채택, 둘 다 없으면 null.
	module := strings.TrimSpace(c.Module)
	moduleShort := strings.TrimSpace(c.ModuleShort)
	if module != "" && containsCI(src, module) {
		e.Module = module
		if moduleShort != "" && containsCI(src, moduleShort) {
			e.ModuleShort = moduleShort
		} else {
			e.ModuleShort = module
		}
		e.Provenance["module"] = "advisory"
	} else if moduleShort != "" && containsCI(src, moduleShort) {
		e.Module = moduleShort
		e.ModuleShort = moduleShort
		e.Provenance["module"] = "advisory"
	} else {
		e.Provenance["module"] = "not_specified_in_source"
	}

	// function: 메서드/심볼이 소스에 명시된 경우만(대개 null).
	fn := strings.TrimSpace(c.Function)
	if fn != "" && containsCI(src, fn) {
		e.Function = &fn
		e.Provenance["function"] = "advisory"
	}

	// mechanism: 검증된 span(소스에 substring으로 존재)만 보존. 살아남은 span이 없으면 null.
	var validSpans []scoring.MechanismSpan
	for _, sp := range c.MechanismSpans {
		t := strings.TrimSpace(sp.Text)
		if t != "" && containsCI(src, t) {
			validSpans = append(validSpans, scoring.MechanismSpan{Text: t, Src: sp.Src})
		}
	}
	if len(validSpans) > 0 {
		e.Mechanism = strings.TrimSpace(c.Mechanism)
		e.MechanismShort = strings.TrimSpace(c.MechanismShort)
		e.MechanismSpans = validSpans
		e.Provenance["mechanism"] = "advisory"
	} else {
		e.Provenance["mechanism"] = "not_specified_in_source"
	}

	// fixed_versions: 소스에 버전 문자열이 실제로 등장하는 것만(환각 버전 차단).
	for _, v := range c.FixedVersions {
		v = strings.TrimSpace(v)
		if v != "" && strings.Contains(source, v) {
			e.FixedVersions = append(e.FixedVersions, v)
		}
	}

	// preconditions: advisory 근거가 있을 때(span 검증 통과)만 보존.
	if len(validSpans) > 0 && len(c.Preconditions) > 0 {
		for i := range c.Preconditions {
			if c.Preconditions[i].Provenance == "" {
				c.Preconditions[i].Provenance = "advisory"
			}
		}
		e.Preconditions = c.Preconditions
		e.Provenance["preconditions"] = "advisory"
	}

	// vuln_class 라벨: 구조화 CWE 보조 라벨. 소스 검증 불필요(요약 라벨).
	e.VulnClassLabel = strings.TrimSpace(c.VulnClassLabel)
	e.VulnClassLabelShort = strings.TrimSpace(c.VulnClassLabelShort)
}

// buildCVSSInfo — 단일 출처(NVD/global) vector 기준 CVSSInfo. scope는 벡터에서 도출.
func buildCVSSInfo(vector string, score float64, scopeChanged bool) *scoring.CVSSInfo {
	if vector == "" && score == 0 {
		return nil
	}
	scope := "U"
	if scopeChanged {
		scope = "C"
	}
	var bs *float64
	if score > 0 {
		bs = &score
	}
	return &scoring.CVSSInfo{
		Sources: []scoring.CVSSSource{{Source: "nvd", Vector: vector, BaseScore: bs, Scope: scope}},
		Resolved: scoring.CVSSResolved{
			Policy:       "single_source",
			Scope:        scope,
			DisplayScore: score,
		},
	}
}

// buildSignals — KEV/PoC/EPSS 신호. 우선순위 kev > public_poc > epss.
func buildSignals(inKEV, inPoC bool, epss *float64) *scoring.EnrichSignals {
	return &scoring.EnrichSignals{
		KEV:       inKEV,
		PublicPoC: inPoC,
		EPSS:      epss,
		Priority:  []string{"kev", "public_poc", "epss"},
	}
}

// hashSource — source 본문 + CVSS 벡터의 SHA-256 (출처 변경 감지용).
func hashSource(source, vector string) string {
	h := sha256.Sum256([]byte(source + "\x00" + vector))
	return hex.EncodeToString(h[:])
}

// containsCI — needle(소문자화)이 src(이미 소문자) 안에 substring으로 있는지.
func containsCI(srcLower, needle string) bool {
	return strings.Contains(srcLower, strings.ToLower(needle))
}

// extractJSONObject — raw 텍스트에서 첫 '{' ~ 마지막 '}' 구간을 잘라낸다(중첩 객체 지원).
// vlm.jsonRe(중첩 미지원)와 달리 enrichment 같은 nested JSON에 쓴다.
func extractJSONObject(raw string) string {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return ""
	}
	return raw[start : end+1]
}
