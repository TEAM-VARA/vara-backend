// Package advisory fetches vendor security-advisory pages (referenced by NVD)
// and returns their plain-text body for CVE narrative enrichment 추출.
//
// 신뢰·안전 가드(설계서 §5, §2-6):
//   - HTTPS 전용. 사설/루프백 호스트·IP 리터럴 차단(SSRF 방지).
//   - 호스트 allowlist(알려진 advisory 도메인)만 허용 — 임의 URL fetch 금지.
//   - 응답 크기 캡 + HTML 태그 제거 후 텍스트만 반환(LLM 토큰 절약).
package advisory

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	fetchTimeout = 15 * time.Second
	maxRawBytes  = 1 << 20 // 1MB raw 응답 캡
	maxTextRunes = 20000   // advisory당 텍스트 캡(LLM 입력 토큰 절약)
)

// allowedSuffixes — advisory fetch를 허용하는 호스트 접미사. host == suffix 또는 *.suffix 매칭.
var allowedSuffixes = []string{
	"apache.org",       // *.apache.org, lists.apache.org, tomcat.apache.org
	"github.com",       // GHSA: github.com/<org>/<repo>/security/advisories/GHSA-...
	"github.io",
	"nvd.nist.gov",
	"cve.org",
	"cve.mitre.org",
	"redhat.com",       // access.redhat.com
	"ubuntu.com",
	"debian.org",
	"gitlab.com",
	"openwall.com",     // oss-security
	"kb.cert.org",
	"security.snyk.io",
}

// Client fetches advisory pages over HTTPS.
type Client struct {
	http *http.Client
}

// NewClient creates an advisory fetch client.
func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: fetchTimeout}}
}

// IsAllowedURL reports whether u is an HTTPS URL on an allowlisted advisory host
// (and not a private/loopback literal). 호출부가 fetch 전 ref 필터링에 쓴다.
func IsAllowedURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" {
		return false
	}
	// IP 리터럴은 거부(SSRF — 사설망 직격 차단). 정상 advisory는 도메인으로 온다.
	if ip := net.ParseIP(host); ip != nil {
		return false
	}
	for _, suf := range allowedSuffixes {
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// FetchText GETs an allowlisted advisory URL and returns its plain-text body.
// 비허용 URL/비-200/크기초과는 에러. graceful: 호출부가 실패를 무시하고 다음 ref로 넘어갈 수 있다.
func (c *Client) FetchText(ctx context.Context, rawURL string) (string, error) {
	if !IsAllowedURL(rawURL) {
		return "", fmt.Errorf("advisory: url not allowed: %s", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "vara-cve-enrichment/1.0")
	req.Header.Set("Accept", "text/html,text/plain;q=0.9,*/*;q=0.5")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("advisory fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("advisory status %d for %s", resp.StatusCode, rawURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRawBytes))
	if err != nil {
		return "", fmt.Errorf("advisory read: %w", err)
	}
	text := htmlToText(string(body))
	if len([]rune(text)) > maxTextRunes {
		text = string([]rune(text)[:maxTextRunes])
	}
	return text, nil
}

var wsRe = regexp.MustCompile(`[ \t]+`)
var blankLineRe = regexp.MustCompile(`\n{3,}`)

// htmlToText strips script/style and tags, unescapes entities, collapses whitespace.
// HTML 파싱 실패(plain text 응답 등)면 원문을 거의 그대로 정리해 반환.
func htmlToText(s string) string {
	doc, err := html.Parse(strings.NewReader(s))
	if err != nil {
		return cleanWhitespace(s)
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "noscript", "head":
				return // 본문 아님 — 스킵
			case "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "section", "article":
				b.WriteString("\n")
			}
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	return cleanWhitespace(b.String())
}

func cleanWhitespace(s string) string {
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimSpace(wsRe.ReplaceAllString(ln, " "))
	}
	s = strings.Join(lines, "\n")
	s = blankLineRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}
