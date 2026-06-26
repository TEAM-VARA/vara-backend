// Package engine 은 AWS IAM 권한상승(privilege-escalation) posture 탐지 엔진이다.
//
// scan_iam_privesc.py 의 평가 로직(와일드카드 매칭, Statement 평가, 위험도 보정,
// 그룹 상속, 관리형 정책 해석, 콤보 판정)을 Go 로 포팅한 것. DB·AWS·flag 에
// 의존하지 않는 순수 패키지이며, 입력은 Snapshot, 출력은 []PrincipalResult + Summary.
package engine

import (
	"bytes"
	"encoding/json"
	"net/url"
	"time"
)

// ---------------------------------------------------------------------------
// 폴리모픽 JSON 헬퍼 — IAM 정책은 Action/Resource 가 문자열 또는 배열,
// Statement 가 단건 또는 배열로 온다(Python as_list 대응).
// ---------------------------------------------------------------------------

// FlexStrings 는 JSON 문자열 또는 문자열 배열을 모두 []string 으로 받는다.
type FlexStrings []string

func (f *FlexStrings) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = nil
		return nil
	}
	if b[0] == '[' {
		var s []string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = s
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*f = FlexStrings{s}
	return nil
}

// FlexStatements 는 Statement 가 단건(object) 또는 배열로 올 수 있는 경우를 흡수한다.
type FlexStatements []Statement

func (f *FlexStatements) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = nil
		return nil
	}
	if b[0] == '[' {
		var s []Statement
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = s
		return nil
	}
	var s Statement
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*f = FlexStatements{s}
	return nil
}

// Statement 의 포인터 필드 = "키 존재" 판별(Python `"Action" in stmt`).
// nil 이면 키 자체가 없음을 뜻한다.
type Statement struct {
	Effect      string          `json:"Effect"`
	Action      *FlexStrings    `json:"Action,omitempty"`
	NotAction   *FlexStrings    `json:"NotAction,omitempty"`
	Resource    *FlexStrings    `json:"Resource,omitempty"`
	NotResource *FlexStrings    `json:"NotResource,omitempty"`
	Principal   json.RawMessage `json:"Principal,omitempty"`
	Condition   map[string]any  `json:"Condition,omitempty"`
}

// PolicyDocument 는 IAM 정책 문서(Version + Statement).
type PolicyDocument struct {
	Version   string         `json:"Version"`
	Statement FlexStatements `json:"Statement"`
}

// normalizeDoc 는 정책 문서(dict 또는 URL-encoded 문자열)를 PolicyDocument 로 정규화한다.
// (Python normalize_doc 대응)
func normalizeDoc(raw json.RawMessage) PolicyDocument {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 || string(b) == "null" {
		return PolicyDocument{}
	}
	switch b[0] {
	case '{':
		var d PolicyDocument
		if err := json.Unmarshal(b, &d); err == nil {
			return d
		}
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return PolicyDocument{}
		}
		// urllib unquote 대응(+ 는 보존) → PathUnescape.
		if dec, err := url.PathUnescape(s); err == nil {
			var d PolicyDocument
			if json.Unmarshal([]byte(dec), &d) == nil {
				return d
			}
		}
		var d PolicyDocument
		if json.Unmarshal([]byte(s), &d) == nil {
			return d
		}
	}
	return PolicyDocument{}
}

// principalHasStar 는 신뢰 정책 Statement 의 Principal 이 '*' 를 포함하는지 본다.
// "*"(문자열) 또는 {"AWS": "*"} / {"AWS": ["*", ...]} 형태를 모두 처리(Python 대응).
func principalHasStar(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(b, &s) == nil {
		return s == "*"
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) == nil {
		for _, v := range m {
			var vs string
			if json.Unmarshal(v, &vs) == nil {
				if vs == "*" {
					return true
				}
				continue
			}
			var vl []string
			if json.Unmarshal(v, &vl) == nil {
				for _, x := range vl {
					if x == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AWS GetAccountAuthorizationDetails 구조체 (키 이름은 응답 그대로).
// ---------------------------------------------------------------------------

type InlinePolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

type AttachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type PermissionsBoundary struct {
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
}

type UserDetail struct {
	UserName                string               `json:"UserName"`
	Arn                     string               `json:"Arn"`
	GroupList               []string             `json:"GroupList"`
	AttachedManagedPolicies []AttachedPolicy     `json:"AttachedManagedPolicies"`
	UserPolicyList          []InlinePolicy       `json:"UserPolicyList"`
	PermissionsBoundary     *PermissionsBoundary `json:"PermissionsBoundary"`
}

type RoleDetail struct {
	RoleName                 string               `json:"RoleName"`
	Arn                      string               `json:"Arn"`
	AttachedManagedPolicies  []AttachedPolicy     `json:"AttachedManagedPolicies"`
	RolePolicyList           []InlinePolicy       `json:"RolePolicyList"`
	AssumeRolePolicyDocument json.RawMessage      `json:"AssumeRolePolicyDocument"`
	PermissionsBoundary      *PermissionsBoundary `json:"PermissionsBoundary"`
}

type GroupDetail struct {
	GroupName               string           `json:"GroupName"`
	Arn                     string           `json:"Arn"`
	AttachedManagedPolicies []AttachedPolicy `json:"AttachedManagedPolicies"`
	GroupPolicyList         []InlinePolicy   `json:"GroupPolicyList"`
}

type PolicyVersion struct {
	VersionId        string          `json:"VersionId"`
	IsDefaultVersion bool            `json:"IsDefaultVersion"`
	Document         json.RawMessage `json:"Document"`
}

type ManagedPolicy struct {
	PolicyName        string          `json:"PolicyName"`
	Arn               string          `json:"Arn"`
	DefaultVersionId  string          `json:"DefaultVersionId"`
	PolicyVersionList []PolicyVersion `json:"PolicyVersionList"`
}

// Snapshot 은 한 계정의 IAM 권한 구성(소스 DB 한 행 또는 GetAccountAuthorizationDetails).
type Snapshot struct {
	AccountID    string
	AccountAlias string
	ScannedAt    time.Time
	Users        []UserDetail
	Roles        []RoleDetail
	Groups       []GroupDetail
	Policies     []ManagedPolicy
}

// ---------------------------------------------------------------------------
// 출력 — JSON 태그는 scan_iam_privesc.py 의 dict 키와 정확히 일치(골든 파리티).
// ---------------------------------------------------------------------------

type Finding struct {
	Type         string   `json:"type"`          // "rule" | "combo"
	ID           string   `json:"id"`
	Action       string   `json:"action"`
	Severity     string   `json:"severity"`      // 보정 후 위험도
	BaseSeverity string   `json:"base_severity"` // 룰 정의상 기본 위험도
	Core         bool     `json:"core"`
	TitleKo      string   `json:"title_ko"`
	Category     string   `json:"category"`
	Notes        []string `json:"notes"`    // 항상 비-nil([] 보장)
	Sources      []string `json:"sources"`  // 항상 비-nil([] 보장)
	AwsDoc       string   `json:"aws_doc"`
}

type PrincipalResult struct {
	Name     string    `json:"name"`
	Arn      string    `json:"arn"`
	Kind     string    `json:"kind"` // user | role | group
	Status   string    `json:"status"`
	Findings []Finding `json:"findings"` // 항상 비-nil([] 보장)
	Notes    []string  `json:"notes"`    // 항상 비-nil([] 보장)
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	Ok       int `json:"ok"`
}
