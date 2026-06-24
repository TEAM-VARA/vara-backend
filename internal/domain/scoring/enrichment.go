package scoring

import (
	"fmt"
	"strings"
	"time"
)

// ============================================================================
// CVE Narrative Enrichment — config-free, per-CVE enrichment object (설계서 §4).
//
// 원칙(설계서 §2):
//   - 추출 ≠ 생성. module/mechanism/function/preconditions 는 advisory 근거가 있을 때만 채운다.
//   - 필드별 nullable 강제. 출처에 없으면 빈 값/nil → 렌더에서 omit.
//   - CVSS 우선. impact/remote/unauth 는 LLM 출력이 아니라 CVSS vector 파싱이 결정한다.
//   - config-free. 이 객체는 클러스터 상태를 모른다. pod별 충족 판정(L2)은 별도.
//
// 이 객체는 CVE 1건당 1회 생성 후 캐시(cve_enrichment 테이블)되어,
// 영향받는 모든 image/pod 시나리오에 재사용된다.
// ============================================================================

// EnrichmentTTL — cve_enrichment 캐시 수명. advisory/fixed_versions 변경 빈도를 고려해 7일.
const EnrichmentTTL = 7 * 24 * time.Hour

// EnrichmentExtractorVersion — 추출 파이프라인 버전. 프롬프트/스키마 변경 시 올려 캐시 무효화.
// v2: rendered.card(T0 노드 카드 한 줄) 추가 — v1 캐시는 카드가 없어 재추출 필요.
const EnrichmentExtractorVersion = "v2"

// ConfidenceUnconfirmed — L2(config/reachability) 미구현 동안 모든 enrichment의 기본 confidence.
// 비대칭 원칙(설계서 §2-5): 미확인 ≠ 안전. 강등/dismiss 하지 않는다.
const ConfidenceUnconfirmed = "unconfirmed"

// CVEEnrichment — CVE 1건의 추출 결과 (설계서 §4 스키마). 캐시 단위, config-free.
type CVEEnrichment struct {
	CVEID string `json:"cve_id"`

	// 취약점 클래스 (CWE 기반, 구조화 → 신뢰도 높음)
	VulnClass           []string `json:"vuln_class,omitempty"`
	VulnClassLabel      string   `json:"vuln_class_label,omitempty"`
	VulnClassLabelShort string   `json:"vuln_class_label_short,omitempty"`

	// 영향/접근 (CVSS 파싱이 결정 — LLM 무시)
	Impact string `json:"impact,omitempty"` // RCE | DoS | Info Disclosure | 기타
	Remote bool   `json:"remote"`           // AV:N
	Unauth bool   `json:"unauth"`           // PR:N

	// 취약 컴포넌트 (advisory 추출, nullable)
	Module      string  `json:"module,omitempty"`
	ModuleShort string  `json:"module_short,omitempty"`
	Function    *string `json:"function"` // 메서드/심볼 명시된 경우만. 대개 null.

	// 메커니즘 (advisory 추출 + substring 검증, nullable)
	Mechanism      string          `json:"mechanism,omitempty"`
	MechanismShort string          `json:"mechanism_short,omitempty"`
	MechanismSpans []MechanismSpan `json:"mechanism_spans,omitempty"`

	// 악용 전제 (advisory 추출, 구조체). L2 seam — check_signal 로 무엇을 probe할지 지시.
	Preconditions []Precondition `json:"preconditions,omitempty"`

	// 패치 버전 (advisory 추출)
	FixedVersions []string `json:"fixed_versions,omitempty"`

	// ATT&CK 매핑 (CVSS/CWE 도출, _validated:false)
	Attack *AttackMapping `json:"attack,omitempty"`

	// 보완대책 (fixed_versions + precondition.negation 도출)
	Mitigations []Mitigation `json:"mitigations,omitempty"`

	// CVSS (출처별 vector + 합성 정책)
	CVSS *CVSSInfo `json:"cvss,omitempty"`

	// 신호 (KEV/PoC/EPSS)
	Signals *EnrichSignals `json:"signals,omitempty"`

	// L2 confidence (현재 항상 unconfirmed). 렌더 톤만 변조.
	Confidence string `json:"confidence"`

	// 메타: ATT&CK 매핑은 정책이므로 _validated:false.
	Validated  bool              `json:"_validated"`
	Provenance map[string]string `json:"_provenance,omitempty"`

	// T0 노드 카드 한 줄 (CVE-intrinsic 조립 결과). per-CVE 저장·재사용.
	// finding.scenario(per-pod 프로즈)와 별개의 컴팩트 배지 줄 (설계서 §4, OpenAPI rendered.card).
	Rendered *RenderedText `json:"rendered,omitempty"`
}

// RenderedText — T0 노드 카드용 CVE-intrinsic 한 줄 (신뢰도 배지·pod 상태 제외).
type RenderedText struct {
	Lang string `json:"lang,omitempty"`
	Card string `json:"card"`
}

// MechanismSpan — mechanism 조립에 쓰인 advisory 연속 span (검증 증적).
type MechanismSpan struct {
	Text string `json:"text"`
	Src  string `json:"src"`
}

// Precondition — 악용 요건 1건 (CVE-intrinsic). pod 충족 여부와 분리(L2).
type Precondition struct {
	ID           string `json:"id"`
	Text         string `json:"text"`
	DefaultState string `json:"default_state"`          // disabled | enabled | conditional
	ExploitWhen  string `json:"exploit_when"`           // enabled | present 등 (취약 방향)
	Negation     string `json:"negation,omitempty"`     // 완화책 소스
	CheckSignal  string `json:"check_signal,omitempty"` // L2가 무엇을 probe할지
	Provenance   string `json:"provenance,omitempty"`
}

// AttackMapping — ATT&CK tactic/technique 도출 결과 (정책, _validated:false).
type AttackMapping struct {
	Tactic       string   `json:"tactic,omitempty"`
	TechniqueIDs []string `json:"technique_ids,omitempty"`
	Derivation   string   `json:"_derivation,omitempty"`
	Validated    bool     `json:"_validated"`
}

// Mitigation — 보완대책 1건. card(우측 패널 슬롯) + M-코드 + gating 보유 (설계서 §8).
type Mitigation struct {
	Tier             int    `json:"tier"`
	Action           string `json:"action"`
	AttackMitigation string `json:"attack_mitigation,omitempty"` // M-코드
	Card             string `json:"card"`                        // VULN | CONFIG | NET
	GatedOnConfig    bool   `json:"gated_on_config"`
	Gate             string `json:"gate,omitempty"` // precondition.id
	Source           string `json:"source"`         // fixed_versions | precondition.negation | general
}

// CVSSInfo — 출처별 vector + 합성 정책 (설계서 §4.3).
type CVSSInfo struct {
	Sources  []CVSSSource  `json:"sources,omitempty"`
	Resolved CVSSResolved  `json:"resolved"`
}

// CVSSSource — 출처 하나의 vector/score/scope.
type CVSSSource struct {
	Source    string   `json:"source"` // nvd | apache | ...
	Vector    string   `json:"vector,omitempty"`
	BaseScore *float64 `json:"base_score"`
	Scope     string   `json:"scope,omitempty"` // C(Changed) | U(Unchanged)
}

// CVSSResolved — 합성 결과 (Blast-Radius는 scope를 보수적으로 S:C 가정).
type CVSSResolved struct {
	Policy       string  `json:"policy"`
	Scope        string  `json:"scope,omitempty"`
	DisplayScore float64 `json:"display_score"`
	Note         string  `json:"_note,omitempty"`
}

// EnrichSignals — KEV/PoC/EPSS 신호. 우선순위 kev > public_poc > epss.
type EnrichSignals struct {
	KEV       bool     `json:"kev"`
	KEVAdded  string   `json:"kev_added,omitempty"`
	PublicPoC bool     `json:"public_poc"`
	EPSS      *float64 `json:"epss"`
	Priority  []string `json:"_priority,omitempty"`
}

// ─────────────────────────────────────────
// CVSS 파싱 (LLM보다 우선 — 설계서 §5.3, §13-3)
// ─────────────────────────────────────────

// ParseCVSSFlags — CVSS v3.1/v4.0 벡터에서 시나리오/enrichment 판정 플래그를 추출한다.
//
//	remote(AV:N) / availability(A:H|VA:H) / confidentiality(C:H|VC:H) /
//	scopeChanged(S:C 또는 v4.0 후속시스템 영향) / unauth(PR:N)
//
// "/" 로 토큰 분리 후 키:값 정확 매칭 → "AC:H"가 "C:H"로 오인되는 substring 버그 방지.
func ParseCVSSFlags(vec string) (remote, availability, confidentiality, scopeChanged, unauth bool) {
	m := make(map[string]string)
	for _, tok := range strings.Split(vec, "/") {
		if kv := strings.SplitN(tok, ":", 2); len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	remote = m["AV"] == "N"
	availability = m["A"] == "H" || m["VA"] == "H"
	confidentiality = m["C"] == "H" || m["VC"] == "H"
	scopeChanged = m["S"] == "C" || m["SC"] == "H" || m["SI"] == "H" || m["SA"] == "H"
	unauth = m["PR"] == "N"
	return
}

// rceCWEs — RCE/임의코드실행으로 분류하는 CWE 집합 (impact=RCE 도출용).
var rceCWEs = map[string]bool{
	"CWE-502": true, // 안전하지 않은 역직렬화
	"CWE-94":  true, // 코드 인젝션
	"CWE-95":  true, // eval 인젝션
	"CWE-77":  true, // 명령 인젝션(일반)
	"CWE-78":  true, // OS 명령 인젝션
	"CWE-434": true, // 위험한 파일 업로드
	"CWE-917": true, // EL 인젝션
	"CWE-918": true, // SSRF (간접 RCE 흔함)
}

// dosCWEs — 가용성 영향(DoS)으로 분류하는 CWE.
var dosCWEs = map[string]bool{
	"CWE-400": true, // 자원 고갈
	"CWE-770": true, // 제한 없는 자원 할당
	"CWE-835": true, // 무한 루프
}

// DeriveImpact — CWE + CVSS 영향 플래그로 impact 라벨을 도출한다.
// CVSS가 우선이지만 RCE 판정은 CWE 시그널이 필요(C/I/A만으론 RCE를 못 가린다).
func DeriveImpact(cwes []string, availability, confidentiality bool) string {
	for _, c := range cwes {
		if rceCWEs[strings.ToUpper(strings.TrimSpace(c))] {
			return "RCE"
		}
	}
	for _, c := range cwes {
		if dosCWEs[strings.ToUpper(strings.TrimSpace(c))] {
			return "DoS"
		}
	}
	switch {
	case availability:
		return "DoS"
	case confidentiality:
		return "Info Disclosure"
	default:
		return ""
	}
}

// ─────────────────────────────────────────
// ATT&CK 도출 (설계서 §8.1, _validated:false)
// ─────────────────────────────────────────

// DeriveAttack — impact/remote/unauth(CVSS 산출물)로 ATT&CK technique을 도출한다.
//
//	RCE ∧ remote ∧ unauth ∧ public-facing → T1190 (Exploit Public-Facing Application)
//	클러스터 내 피벗 컨텍스트(remote, public 아님)  → T1210 (Exploitation of Remote Services)
//
// publicFacing 은 enrichment 단계에선 알 수 없으므로(노드별 신호), 보수적으로 remote 면 T1190 후보로 둔다.
// 노드 컨텍스트가 우선이며(설계서 §7.5), _validated:false.
func DeriveAttack(impact string, remote, unauth bool) *AttackMapping {
	if !remote {
		return nil
	}
	a := &AttackMapping{Validated: false}
	if (impact == "RCE") && unauth {
		a.Tactic = "TA0001 Initial Access"
		a.TechniqueIDs = []string{"T1190"}
		a.Derivation = "impact=RCE ∧ remote ∧ unauth → T1190. 클러스터 내 피벗 컨텍스트면 T1210 추가."
	} else {
		a.Tactic = "TA0008 Lateral Movement"
		a.TechniqueIDs = []string{"T1210"}
		a.Derivation = "remote 악용 가능 → T1210(원격 서비스 악용). public-facing이면 T1190."
	}
	return a
}

// ─────────────────────────────────────────
// 보완대책 도출 (설계서 §8.1)
// ─────────────────────────────────────────

// DeriveMitigations — fixed_versions + precondition.negation 으로 tiered 보완대책을 도출한다.
//
//	tier 1 (VULN, M1051) : 패치 업그레이드 — fixed_versions 있을 때
//	tier 2 (CONFIG, M1042): precondition.negation — 전부 gated_on_config
//	tier 3 (NET, M1030)  : 인바운드 제한(NetworkPolicy) — 항상
func DeriveMitigations(fixedVersions []string, pre []Precondition) []Mitigation {
	var out []Mitigation
	if len(fixedVersions) > 0 {
		out = append(out, Mitigation{
			Tier:             1,
			Action:           "패치 업그레이드 (" + strings.Join(fixedVersions, " / ") + ")",
			AttackMitigation: "M1051",
			Card:             "VULN",
			GatedOnConfig:    false,
			Source:           "fixed_versions",
		})
	}
	for _, p := range pre {
		if p.Negation == "" {
			continue
		}
		out = append(out, Mitigation{
			Tier:             2,
			Action:           p.Negation,
			AttackMitigation: "M1042",
			Card:             "CONFIG",
			GatedOnConfig:    true,
			Gate:             p.ID,
			Source:           "precondition.negation",
		})
	}
	out = append(out, Mitigation{
		Tier:             3,
		Action:           "NetworkPolicy로 인바운드 접근 제한",
		AttackMitigation: "M1030",
		Card:             "NET",
		GatedOnConfig:    false,
		Source:           "general",
	})
	return out
}

// ─────────────────────────────────────────
// T0 노드 카드 렌더 (설계서 §4, OpenAPI rendered.card)
// ─────────────────────────────────────────

// BuildRenderedCard — enrichment 필드(전부 CVE-intrinsic)로 T0 노드 카드 한 줄을 조립한다.
//
//	형식: "{컴포넌트} · {클래스 영향} · {CVE-ID} CVSS {점수} · KEV · PoC"
//	예  : "HTTP/2 · DoS · CVE-2023-44487 CVSS 7.5 · KEV · PoC"
//
// finding.scenario(per-pod 프로즈)와 별개의 컴팩트 배지 줄. pod 상태·confidence 배지는 제외.
// 모든 토막은 추출/검증된 값에서만 오므로 환각 0 — 빈 값은 자연히 생략된다(메서드명 생성 금지).
func BuildRenderedCard(e *CVEEnrichment) *RenderedText {
	if e == nil {
		return nil
	}

	// ① 컴포넌트 (module_short → module → "취약 컴포넌트" 폴백)
	comp := e.ModuleShort
	if comp == "" {
		comp = e.Module
	}
	if comp == "" {
		comp = "취약 컴포넌트"
	}

	// ② 클래스 · 영향 (중복이면 한 번만: class="DoS" ∧ impact="DoS" → "DoS")
	class := e.VulnClassLabelShort
	if class == "" {
		class = e.VulnClassLabel
	}
	var kind string
	switch {
	case class != "" && e.Impact != "" && !strings.EqualFold(class, e.Impact):
		kind = class + " " + e.Impact // "역직렬화 RCE"
	case class != "":
		kind = class
	default:
		kind = e.Impact
	}

	// ③ CVE · CVSS
	idSeg := e.CVEID
	if e.CVSS != nil && e.CVSS.Resolved.DisplayScore > 0 {
		idSeg += fmt.Sprintf(" CVSS %.1f", e.CVSS.Resolved.DisplayScore)
	}

	parts := []string{comp}
	if kind != "" {
		parts = append(parts, kind)
	}
	parts = append(parts, idSeg)
	card := strings.Join(parts, " · ")

	// ④ 신호 배지 (우선순위 kev > public_poc, 설계서 §4)
	if e.Signals != nil {
		if e.Signals.KEV {
			card += " · KEV"
		}
		if e.Signals.PublicPoC {
			card += " · PoC"
		}
	}

	return &RenderedText{Lang: "ko", Card: card}
}
