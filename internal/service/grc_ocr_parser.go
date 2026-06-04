package service

import (
	"regexp"
	"strconv"
	"strings"
)

var reMultiSpace = regexp.MustCompile(`\s+`)

// normalizeWhitespace는 여러 공백을 하나로 축소합니다.
func normalizeWhitespace(s string) string {
	return strings.TrimSpace(reMultiSpace.ReplaceAllString(s, " "))
}

// parseOCRToStructured는 OCR 텍스트를 구조화된 map[string]any로 변환합니다.
// fieldNames는 룰의 ComplianceIndicators에서 추출한 필드명 목록입니다.
//
// 2단계 파싱:
//  1. 라인별 key=value, KEY<ws>VALUE 패턴 추출 (터미널/config 형식)
//  2. fieldNames 기반 다중 라인 검색 (테이블 형식 - 필드명과 값이 다른 줄일 수 있음)
func parseOCRToStructured(ocrText string, fieldNames []string) map[string]any {
	result := make(map[string]any)
	lines := strings.Split(ocrText, "\n")

	// Phase 1: 라인별 key=value 및 KEY<whitespace>VALUE 추출
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if kv := parseKeyEqualsValue(line); kv != nil {
			for k, v := range kv {
				if !isGarbageValue(v) {
					result[k] = v
				}
			}
			continue
		}
		if kv := parseKeyWhitespaceValue(line); kv != nil {
			for k, v := range kv {
				if !isGarbageValue(v) {
					result[k] = v
				}
			}
		}
	}

	// Phase 2: fieldNames 기반 다중 라인 검색
	// 아직 찾지 못한 필드만 검색
	for _, field := range fieldNames {
		if field == "" {
			continue
		}
		if _, exists := result[field]; exists {
			continue
		}
		// 퍼지 매칭으로도 이미 존재하는지 확인
		if _, found := fuzzyFindKey(result, field); found {
			continue
		}
		if v := findFieldInText(ocrText, field, lines); v != nil {
			result[field] = v
		}
	}

	return result
}

// findFieldInText는 OCR 텍스트에서 필드명을 찾고 값을 추출합니다.
// 같은 줄에서 값을 찾고, 없으면 다음 비어있지 않은 줄에서 찾습니다.
// 공백 정규화를 적용하여 Tesseract의 불규칙 공백을 처리합니다.
func findFieldInText(fullText string, field string, lines []string) any {
	fieldNorm := normalizeWhitespace(field)
	fieldLower := strings.ToLower(fieldNorm)
	// _ ↔ 공백 대체 버전 (OCR이 밑줄을 공백으로 읽는 경우 대비)
	fieldAlt := strings.ReplaceAll(fieldLower, "_", " ")

	for i, line := range lines {
		lineTrimmed := normalizeWhitespace(strings.TrimSpace(line))
		if lineTrimmed == "" {
			continue
		}
		lineLower := strings.ToLower(lineTrimmed)

		// 원본 필드명으로 검색
		idx := strings.Index(lineLower, fieldLower)
		matchLen := len(fieldNorm)
		// 실패 시 _ → 공백 대체 버전으로 재시도
		if idx < 0 && fieldAlt != fieldLower {
			idx = strings.Index(lineLower, fieldAlt)
			matchLen = len(strings.ReplaceAll(fieldNorm, "_", " "))
		}
		if idx < 0 {
			continue
		}

		// 필드명 뒤의 텍스트 추출
		rest := strings.TrimSpace(lineTrimmed[idx+matchLen:])
		// 괄호로 시작하는 부분 제거: "Lockout Duration (minutes)" → "(minutes)" 스킵
		rest = stripParenPrefix(rest)
		rest = strings.TrimLeft(rest, ":=|.")
		rest = strings.TrimSpace(rest)

		if rest != "" {
			return normalizeValue(rest)
		}

		// 같은 줄에 값이 없으면 → 다음 비어있지 않은 줄에서 값 추출
		for j := i + 1; j < len(lines); j++ {
			nextLine := strings.TrimSpace(lines[j])
			if nextLine == "" {
				continue
			}
			// 다음 줄이 다른 필드명이면 스킵
			if looksLikeFieldName(nextLine) {
				break
			}
			return normalizeValue(nextLine)
		}
	}
	return nil
}

// stripParenPrefix는 "(minutes)" 같은 괄호 접두사를 제거합니다.
func stripParenPrefix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "(") {
		end := strings.Index(s, ")")
		if end >= 0 && end+1 < len(s) {
			return strings.TrimSpace(s[end+1:])
		}
		// 괄호만 있고 뒤에 값이 없음
		if end >= 0 {
			return ""
		}
	}
	return s
}

// looksLikeFieldName는 줄이 필드명처럼 보이는지 판단합니다.
// 숫자로만 이루어진 줄은 값이지 필드명이 아닙니다.
func looksLikeFieldName(line string) bool {
	line = strings.TrimSpace(line)
	// 숫자, boolean, 단순 값이면 필드명이 아님
	if _, err := strconv.ParseFloat(line, 64); err == nil {
		return false
	}
	lower := strings.ToLower(line)
	if lower == "true" || lower == "false" || lower == "enabled" || lower == "disabled" || lower == "yes" || lower == "no" {
		return false
	}
	// 숫자로 시작하면 값일 가능성 높음 ("90 days", "10 characters")
	if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
		return false
	}
	return true
}

var reKeyEquals = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+)$`)

// parseKeyEqualsValue는 "minlen = 10" 또는 "dcredit=-1" 패턴을 파싱합니다.
func parseKeyEqualsValue(line string) map[string]any {
	m := reKeyEquals.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	return map[string]any{
		strings.TrimSpace(m[1]): normalizeValue(strings.TrimSpace(m[2])),
	}
}

var reKeyWS = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.]*)\s+(.+)$`)

// parseKeyWhitespaceValue는 "PASS_MAX_DAYS    90" 패턴을 파싱합니다.
func parseKeyWhitespaceValue(line string) map[string]any {
	m := reKeyWS.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	return map[string]any{
		strings.TrimSpace(m[1]): normalizeValue(strings.TrimSpace(m[2])),
	}
}

// normalizeValue는 문자열 값을 적절한 타입으로 변환합니다.
// "90 days" → 90, "Enabled" → "Enabled", "-1" → -1
func normalizeValue(raw string) any {
	raw = strings.TrimSpace(raw)

	// 숫자 단위 제거: "90 days", "10 characters", "5 invalid logon attempts"
	cleaned := stripTrailingUnits(raw)

	// 정수 변환 시도
	if n, err := strconv.ParseInt(cleaned, 10, 64); err == nil {
		return n
	}
	// 실수 변환 시도
	if f, err := strconv.ParseFloat(cleaned, 64); err == nil {
		return f
	}
	// 불리언 변환
	lower := strings.ToLower(raw)
	if lower == "true" || lower == "enabled" || lower == "yes" {
		return true
	}
	if lower == "false" || lower == "disabled" || lower == "no" {
		return false
	}

	return raw
}

// isGarbageValue는 OCR 노이즈로 인한 의미 없는 값인지 판단합니다.
// 단일 특수문자(%, #, *, @ 등)는 OCR이 숫자나 공백을 misread한 결과이므로
// Phase 1에서 저장하지 않고 Phase 2에서 재검색할 수 있도록 합니다.
func isGarbageValue(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false // 숫자, bool 등은 garbage가 아님
	}
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return true
	}
	// 단일 문자이면서 알파벳/숫자가 아닌 경우 → garbage
	if len(s) == 1 {
		c := s[0]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return true
		}
	}
	return false
}

var reLeadingNumber = regexp.MustCompile(`^(-?\d+)`)

// stripTrailingUnits는 "90 days" → "90", "10 characters" → "10" 등의 변환을 수행합니다.
func stripTrailingUnits(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, " ") {
		return s
	}
	m := reLeadingNumber.FindString(s)
	if m != "" {
		return m
	}
	return s
}

// fuzzyFindKey는 OCR 오독을 보상하기 위해 맵에서 유사한 키를 검색합니다.
// 문자열 길이에 따라 허용 오차를 동적으로 조정합니다:
//   - < 8자: 최대 1글자 차이
//   - 8~14자: 최대 2글자 차이
//   - 15자 이상: 최대 3글자 차이 (OCR이 긴 키에서 더 많이 틀림)
//
// 또한 _ ↔ 공백 차이는 무시합니다 (OCR이 밑줄을 공백으로 읽는 경우).
func fuzzyFindKey(m map[string]any, target string) (any, bool) {
	targetLower := strings.ToLower(target)
	targetNorm := strings.ReplaceAll(targetLower, " ", "_")

	for k, v := range m {
		kLower := strings.ToLower(k)
		kNorm := strings.ReplaceAll(kLower, " ", "_")

		if kNorm == targetNorm {
			return v, true
		}
		// 길이가 같을 때만 글자별 비교 (치환 오류 검출)
		if len(kNorm) == len(targetNorm) {
			maxDiffs := fuzzyThreshold(len(targetNorm))
			diffs := 0
			for i := range kNorm {
				if kNorm[i] != targetNorm[i] {
					diffs++
					if diffs > maxDiffs {
						break
					}
				}
			}
			if diffs > 0 && diffs <= maxDiffs {
				return v, true
			}
		}
	}
	return nil, false
}

// fuzzyThreshold는 문자열 길이에 따른 허용 오차를 반환합니다.
func fuzzyThreshold(length int) int {
	switch {
	case length >= 15:
		return 3
	case length >= 8:
		return 2
	default:
		return 1
	}
}

// extractFieldNames는 ComplianceIndicators에서 필드명 목록을 추출합니다.
func extractFieldNames(indicators []Indicator) []string {
	var names []string
	for _, ind := range indicators {
		if ind.Field != "" {
			names = append(names, ind.Field)
		}
	}
	return names
}
