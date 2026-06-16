package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// deps.dev API 클라이언트 (Open Source Insights)
//
// API 문서: https://docs.deps.dev/api/v3/
// 기본 엔드포인트: https://api.deps.dev/v3
//
// 용도(3단계): 패키지의 모든 버전 + 각 버전 릴리스 날짜(publishedAt)를 수집.
//   - GetPackage 1콜로 전 버전 날짜를 받음 → 릴리스 주기 / 보안 대응속도 계산용.
//
// 인증 불필요(무료 공개 API). OSV가 주는 fixed 버전의 "릴리스 날짜"를 채우는 소스.

const (
	defaultBaseURL = "https://api.deps.dev/v3"
	defaultTimeout = 20 * time.Second
)

// Client는 deps.dev API 호출 클라이언트입니다.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient는 기본 설정으로 Client를 생성합니다.
func NewClient() *Client {
	return &Client{
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// VersionRelease는 한 패키지 버전과 그 릴리스 시각입니다.
type VersionRelease struct {
	Version     string     `json:"version"`
	PublishedAt *time.Time `json:"published_at,omitempty"` // 없을 수 있음
}

// getPackageResponse는 GetPackage API 응답의 일부입니다(우리가 쓰는 필드만).
type getPackageResponse struct {
	Versions []struct {
		VersionKey struct {
			Version string `json:"version"`
		} `json:"versionKey"`
		PublishedAt string `json:"publishedAt"`
	} `json:"versions"`
}

// GetPackage는 (system, name) 패키지의 모든 버전 + 릴리스 날짜를 반환합니다.
//
//	system: MAVEN | NPM | PYPI | GO | CARGO | RUBYGEMS | NUGET
//	name:   deps.dev 정규 패키지명 (Maven은 "group:artifact")
func (c *Client) GetPackage(ctx context.Context, system, name string) ([]VersionRelease, error) {
	// 패키지명은 한 path segment로 전부 인코딩 (':' → %3A, '/' → %2F, '@' → %40)
	endpoint := fmt.Sprintf("%s/systems/%s/packages/%s",
		c.baseURL, url.QueryEscape(system), url.QueryEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("deps.dev request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 패키지를 deps.dev가 모름 → 빈 결과 (에러 아님)
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("deps.dev status %d: %s", resp.StatusCode, string(body))
	}

	var pkg getPackageResponse
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("decode deps.dev response: %w", err)
	}

	out := make([]VersionRelease, 0, len(pkg.Versions))
	for _, v := range pkg.Versions {
		vr := VersionRelease{Version: v.VersionKey.Version}
		if v.PublishedAt != "" {
			if t, err := time.Parse(time.RFC3339, v.PublishedAt); err == nil {
				vr.PublishedAt = &t
			}
		}
		out = append(out, vr)
	}
	return out, nil
}

// ─────────────────────────────────────────
// PURL → deps.dev (system, name) 매핑
// ─────────────────────────────────────────

// PurlToDepsDev는 PURL을 deps.dev (system, name)으로 변환합니다.
//
// 지원: maven, npm, pypi, golang, cargo, gem, nuget.
// OS 패키지(deb/apk/rpm 등) 및 미지원 타입은 ok=false (deps.dev 커버리지 밖).
//
// 예: pkg:maven/org.springframework/spring-beans@5.2.15.RELEASE
//     → ("MAVEN", "org.springframework:spring-beans", true)
func PurlToDepsDev(purl string) (system, name string, ok bool) {
	s := strings.TrimSpace(purl)
	s = strings.TrimPrefix(s, "pkg:")
	if s == "" {
		return "", "", false
	}
	// 버전/퀄리파이어 제거: '@' 이후, '?' 이후 잘라냄
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	// s = "type/namespace.../name"
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return "", "", false
	}
	ptype := strings.ToLower(s[:slash])
	rest := s[slash+1:]
	if rest == "" {
		return "", "", false
	}

	// PURL 컴포넌트는 percent-encoded일 수 있음 → 디코드
	decode := func(x string) string {
		if d, err := url.PathUnescape(x); err == nil {
			return d
		}
		return x
	}

	parts := strings.Split(rest, "/")
	for i := range parts {
		parts[i] = decode(parts[i])
	}

	switch ptype {
	case "maven":
		// namespace=group, name=artifact → "group:artifact"
		if len(parts) < 2 {
			return "", "", false
		}
		group := strings.Join(parts[:len(parts)-1], ".")
		artifact := parts[len(parts)-1]
		return "MAVEN", group + ":" + artifact, true
	case "npm":
		// scope 있으면 "@scope/name", 없으면 "name"
		return "NPM", strings.Join(parts, "/"), true
	case "pypi":
		return "PYPI", parts[len(parts)-1], true
	case "golang", "go":
		// 전체 모듈 경로
		return "GO", strings.Join(parts, "/"), true
	case "cargo":
		return "CARGO", parts[len(parts)-1], true
	case "gem":
		return "RUBYGEMS", parts[len(parts)-1], true
	case "nuget":
		return "NUGET", parts[len(parts)-1], true
	default:
		// deb, apk, rpm, generic 등 → deps.dev 미지원
		return "", "", false
	}
}
