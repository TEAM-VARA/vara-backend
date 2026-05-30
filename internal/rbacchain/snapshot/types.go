// Package snapshot - 공통 타입.
//
// Python 구현의 snapshot dict (psycopg2 출력 + JSON 직렬화)와 1:1로 호환되는
// Go 타입. JSON unmarshal 후 그대로 사용 가능.
//
// Permission, NullString 은 Python frozen dataclass 의 등가물.
// map key·struct comparison 가능한 비교 가능 타입만 사용한다.
package snapshot

import (
	"encoding/json"
)

// NullString — Python 의 (Optional[str]) 즉 `str | None` 등가.
// Value 만으로는 빈 문자열 ""(name="") 과 None 구분 불가하므로 IsNull 플래그 필수.
// JSON 에서 null 이면 IsNull=true, 문자열이면 IsNull=false.
type NullString struct {
	Value  string
	IsNull bool
}

// Null - 편의 생성자.
func Null() NullString { return NullString{IsNull: true} }

// S - 비-null 문자열 생성자.
func S(v string) NullString { return NullString{Value: v} }

// MarshalJSON — null 또는 string.
func (n NullString) MarshalJSON() ([]byte, error) {
	if n.IsNull {
		return []byte("null"), nil
	}
	return json.Marshal(n.Value)
}

// UnmarshalJSON — null 또는 string.
func (n *NullString) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		n.IsNull = true
		n.Value = ""
		return nil
	}
	if err := json.Unmarshal(b, &n.Value); err != nil {
		return err
	}
	n.IsNull = false
	return nil
}

// Equal — 두 NullString이 의미상 동일한가.
func (n NullString) Equal(o NullString) bool {
	if n.IsNull != o.IsNull {
		return false
	}
	if n.IsNull {
		return true
	}
	return n.Value == o.Value
}

// ----------------------------------------------------------------------------
// Permission — Python fixpoint.permissions.Permission 1:1.
// 모두 비교 가능 필드 → map key, == 비교 가능.
// ----------------------------------------------------------------------------

type Permission struct {
	APIGroup       string     `json:"api_group"`
	Resource       string     `json:"resource"`
	Verb           string     `json:"verb"`
	Namespace      NullString `json:"namespace"`
	ResourceName   NullString `json:"resource_name"`
	NonResourceURL NullString `json:"non_resource_url"`
}

// FromDict — Python Permission.from_dict 등가. dict 가 아니라 이미 unmarshal 된
// PermissionDict (provenance 포함된 권한 항목)에서 Permission 본체만 추출.
func PermissionFromDict(d map[string]any) Permission {
	return Permission{
		APIGroup:       getString(d, "api_group"),
		Resource:       getString(d, "resource"),
		Verb:           getString(d, "verb"),
		Namespace:      getNullString(d, "namespace"),
		ResourceName:   getNullString(d, "resource_name"),
		NonResourceURL: getNullString(d, "non_resource_url"),
	}
}

func getString(d map[string]any, k string) string {
	v, ok := d[k]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func getNullString(d map[string]any, k string) NullString {
	v, ok := d[k]
	if !ok || v == nil {
		return Null()
	}
	s, ok := v.(string)
	if !ok {
		return Null()
	}
	return S(s)
}

// SAKey — (namespace, name) 튜플 등가. struct 이므로 map key 가능.
type SAKey struct {
	Namespace string
	Name      string
}

// String — "ns/name" 형식.
func (s SAKey) String() string {
	return s.Namespace + "/" + s.Name
}
