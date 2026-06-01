// Package ocr provides a client for invoking the Tesseract CLI tool
// to extract text from images (PNG, JPG, etc.).
//
// tesseract 바이너리를 exec로 호출하여 이미지에서 텍스트를 추출합니다.
// CGO 없이 동작합니다 (CLI 래퍼 방식).
package ocr

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Client는 Tesseract CLI를 래핑하는 클라이언트입니다.
type Client struct {
	BinaryPath string
	Languages  string // e.g. "eng+kor"
	Timeout    time.Duration
}

// NewClient는 기본 설정으로 Client를 생성합니다.
func NewClient() *Client {
	return &Client{
		BinaryPath: "tesseract",
		Languages:  "eng+kor",
		Timeout:    30 * time.Second,
	}
}

// CheckBinary는 tesseract 바이너리가 실행 가능한지 확인합니다.
func (c *Client) CheckBinary(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, c.BinaryPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tesseract binary check failed: %w (output: %s)", err, string(out))
	}
	return nil
}

// ExtractText는 이미지 파일에서 OCR로 텍스트를 추출합니다.
func (c *Client) ExtractText(ctx context.Context, imagePath string) (string, error) {
	if imagePath == "" {
		return "", errors.New("imagePath is required")
	}

	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.BinaryPath, imagePath, "stdout", "-l", c.Languages, "--psm", "6")
	out, err := cmd.Output() // stdout only — stderr contains Tesseract diagnostics
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("tesseract OCR failed (exit %d): %s: %w",
				exitErr.ExitCode(), string(exitErr.Stderr), err)
		}
		return "", fmt.Errorf("tesseract exec failed: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
