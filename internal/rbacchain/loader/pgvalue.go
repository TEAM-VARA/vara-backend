// pgvalue.go — pgx 가 돌려준 컬럼 값을 DBeaver export(psycopg2 RealDictCursor) 와
// 동일한 표현으로 정규화한다.
//
// from_vara_db.go 의 normalizeValue 1:1 (SSH/CLI 의존 없는 순수 부분만 발췌).
// 이걸 통과해야 PostgresLoader 가 만든 row dict 가 JSON 파일 경로와 같은 모양이 되어
// BuildSnapshotFromRaw 가 동일한 snapshot 을 만든다.
package loader

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// normalizeValue — pgx Values() 결과 → DBeaver export 등가 표현.
//
//	timestamp/timestamptz → ISO8601 문자열 (microsecond)
//	jsonb([]byte)         → 디코드된 map/list (이미 디코드돼 있으면 그대로)
//	uuid([16]byte)        → "xxxxxxxx-....." 문자열
//	bytea([]byte, 비JSON) → base64 문자열
func normalizeValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case time.Time:
		return isoFormat(x)
	case []byte:
		if looksLikeJSON(x) {
			var decoded any
			if err := json.Unmarshal(x, &decoded); err == nil {
				return decoded
			}
		}
		return base64.StdEncoding.EncodeToString(x)
	case [16]byte:
		return formatUUID(x[:])
	case map[string]any, []any:
		// pgx 가 jsonb 를 이미 디코드한 경우 — 그대로 통과.
		return v
	case int16:
		return float64(x) // JSON number 와 동일 표현(float64)으로 통일
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case int:
		return float64(x)
	default:
		if s, ok := v.(fmt.Stringer); ok {
			return s.String()
		}
		return v
	}
}

func looksLikeJSON(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	c := b[0]
	return c == '{' || c == '[' || c == '"' || c == 'n' || c == 't' || c == 'f' ||
		(c >= '0' && c <= '9') || c == '-'
}

// isoFormat — Python datetime.isoformat 출력 형식.
//
//	nanosecond == 0 → "2026-05-22T08:03:12+00:00"
//	nanosecond  > 0 → "2026-05-22T08:03:12.123456+00:00"  (microsecond 6자리)
func isoFormat(t time.Time) string {
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05") + formatTZOffset(t)
	}
	return t.Format("2006-01-02T15:04:05.000000") + formatTZOffset(t)
}

func formatTZOffset(t time.Time) string {
	_, off := t.Zone()
	if off == 0 {
		return "+00:00"
	}
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	hh := off / 3600
	mm := (off % 3600) / 60
	return fmt.Sprintf("%s%02d:%02d", sign, hh, mm)
}

func formatUUID(b []byte) string {
	if len(b) != 16 {
		return base64.StdEncoding.EncodeToString(b)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
