// Package pdfext provides PDF text extraction via pdftotext CLI.
//
// poppler-utils의 pdftotext 바이너리를 exec로 호출합니다.
// CGO 없이 동작합니다 (CLI 래퍼 방식).
package pdfext

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ExtractText는 pdftotext CLI로 PDF에서 텍스트를 추출합니다.
func ExtractText(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// pdftotext <input> - : stdout으로 출력
	cmd := exec.CommandContext(ctx, "pdftotext", "-layout", path, "-")
	out, err := cmd.Output() // stdout only
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("pdftotext failed (exit %d): %s: %w",
				exitErr.ExitCode(), string(exitErr.Stderr), err)
		}
		return "", fmt.Errorf("pdftotext exec failed: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

// CheckBinary는 pdftotext 바이너리가 존재하는지 확인합니다.
func CheckBinary(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "pdftotext", "-v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// pdftotext -v는 exit code 0이 아닐 수 있음 (버전 출력 후 종료)
		// stderr에 버전이 출력되면 OK
		if strings.Contains(string(out), "pdftotext") {
			return nil
		}
		return fmt.Errorf("pdftotext binary check failed: %w (output: %s)", err, string(out))
	}
	return nil
}

// IsTextEmpty는 추출된 텍스트가 의미 있는 내용인지 판단합니다.
func IsTextEmpty(text string) bool {
	cleaned := strings.TrimSpace(text)
	if len(cleaned) < 20 {
		return true
	}
	nonPrintable := 0
	for _, r := range cleaned {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(cleaned)) > 0.3
}
