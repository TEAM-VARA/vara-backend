package engine

import (
	"regexp"
	"strings"
	"sync"
)

var (
	reCacheMu sync.Mutex
	reCache   = map[string]*regexp.Regexp{}
)

// actionMatches 는 정책 액션 패턴(granted: "*", "iam:*", "iam:Create*", 정확명)이
// 룰셋의 정확한 액션(target)을 매칭하는지 대소문자 무시로 판정한다.
// (Python action_matches 대응: re.escape 후 \*→.*, \?→. , ^…$ 앵커)
func actionMatches(granted, target string) bool {
	g := strings.ToLower(strings.TrimSpace(granted))
	t := strings.ToLower(strings.TrimSpace(target))
	if g == "*" {
		return true
	}
	return compilePattern(g).MatchString(t)
}

func compilePattern(g string) *regexp.Regexp {
	reCacheMu.Lock()
	defer reCacheMu.Unlock()
	if re, ok := reCache[g]; ok {
		return re
	}
	q := regexp.QuoteMeta(g)
	q = strings.ReplaceAll(q, `\*`, `.*`)
	q = strings.ReplaceAll(q, `\?`, `.`)
	re := regexp.MustCompile("^" + q + "$")
	reCache[g] = re
	return re
}

// coversAction 은 Statement 의 Action/NotAction 이 target 을 포함하는지 본다.
// (Python statement_covers_action: Action 우선, 없으면 NotAction 의 여집합)
func (s Statement) coversAction(target string) bool {
	if s.Action != nil {
		for _, a := range *s.Action {
			if actionMatches(a, target) {
				return true
			}
		}
		return false
	}
	if s.NotAction != nil {
		for _, a := range *s.NotAction {
			if actionMatches(a, target) {
				return false
			}
		}
		return true
	}
	return false
}

// resolveStar 는 Resource(없으면 NotResource, 둘 다 없으면 "*")가 와일드카드를 포함하는지 본다.
// (Python: resource = stmt.get("Resource", stmt.get("NotResource", "*")); resource_has_star)
func (s Statement) resolveStar() bool {
	res := s.Resource
	if res == nil {
		res = s.NotResource
	}
	if res == nil {
		return true // 기본값 "*"
	}
	for _, r := range *res {
		if strings.Contains(r, "*") {
			return true
		}
	}
	return false
}
