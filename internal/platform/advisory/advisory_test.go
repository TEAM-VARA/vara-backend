package advisory

import "testing"

func TestIsAllowedURL(t *testing.T) {
	allowed := []string{
		"https://tomcat.apache.org/security-9.html",
		"https://lists.apache.org/thread/abc",
		"https://github.com/foo/bar/security/advisories/GHSA-xxxx",
		"https://access.redhat.com/security/cve/CVE-2025-1",
		"https://nvd.nist.gov/vuln/detail/CVE-2025-1",
	}
	for _, u := range allowed {
		if !IsAllowedURL(u) {
			t.Errorf("expected allowed: %s", u)
		}
	}

	denied := []string{
		"http://tomcat.apache.org/x",          // 비-HTTPS
		"https://evil.com/advisory",           // 비-allowlist 호스트
		"https://169.254.169.254/latest/meta", // IP 리터럴(SSRF)
		"https://localhost/x",                 // 루프백
		"https://apache.org.evil.com/x",       // 접미사 위장
		"ftp://apache.org/x",                  // 비-HTTP 스킴
		"not a url at all",
	}
	for _, u := range denied {
		if IsAllowedURL(u) {
			t.Errorf("expected denied: %s", u)
		}
	}
}

func TestHtmlToText(t *testing.T) {
	html := `<html><head><style>.x{color:red}</style></head>
	<body><h1>Title</h1><script>alert(1)</script><p>Hello&nbsp;World</p></body></html>`
	got := htmlToText(html)
	if got == "" {
		t.Fatal("htmlToText returned empty")
	}
	if contains(got, "alert(1)") || contains(got, "color:red") {
		t.Errorf("script/style content must be stripped, got %q", got)
	}
	if !contains(got, "Title") || !contains(got, "Hello") || !contains(got, "World") {
		t.Errorf("body text must survive, got %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
