// Package trivy provides a client for invoking the Trivy CLI tool
// to scan container images and produce SBOM + vulnerability data.
//
// Trivy 자체 JSON 형식을 사용하여 SBOM과 CVE 정보를 한 번에 수집합니다.
// 백엔드 컨테이너 내부에 설치된 trivy 바이너리를 exec로 호출합니다.
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Client는 Trivy CLI를 래핑하는 클라이언트입니다.
type Client struct {
	// BinaryPath는 trivy 실행 파일 경로입니다. 기본값: "trivy"
	BinaryPath string

	// ScanTimeout은 단일 스캔의 최대 허용 시간입니다.
	ScanTimeout time.Duration

	// CacheDir은 trivy DB 캐시 디렉토리입니다.
	// 비워두면 trivy 기본값 사용 (~/.cache/trivy).
	CacheDir string

	// DisableJavaDB는 Java/JAR 분석을 비활성화합니다.
	// Java DB는 866MB+로 매우 크고, Java 컴포넌트 없는 이미지엔 불필요.
	// 디스크가 충분하고 Java 이미지를 분석해야 할 때만 false.
	DisableJavaDB bool
}

// NewClient는 기본 설정으로 Client를 생성합니다.
func NewClient() *Client {
	return &Client{
		BinaryPath:    "trivy",
		ScanTimeout:   10 * time.Minute,
		CacheDir:      "/var/cache/trivy",
		DisableJavaDB: true, // 기본값: Java 분석 비활성화 (디스크 절약)
	}
}

// ScanResult는 trivy의 raw JSON 결과를 나타냅니다.
type ScanResult struct {
	Raw          json.RawMessage
	Image        string
	Digest       string
	ScanDuration time.Duration
}

// ScanImage는 주어진 이미지를 trivy로 스캔합니다.
//
// digest가 비어있지 않으면 image@digest 형식으로 호출하여
// 정확한 이미지를 스캔하도록 보장합니다.
func (c *Client) ScanImage(ctx context.Context, image, digest string) (*ScanResult, error) {
	if image == "" {
		return nil, errors.New("image is required")
	}

	target := image
	if digest != "" {
		target = stripTag(image) + "@" + digest
	}

	scanCtx, cancel := context.WithTimeout(ctx, c.ScanTimeout)
	defer cancel()

	args := []string{
		"image",
		"--format", "json",
		"--quiet",
		"--timeout", c.ScanTimeout.String(),
		"--scanners", "vuln",
	}

	if c.CacheDir != "" {
		args = append(args, "--cache-dir", c.CacheDir)
	}

	// Java 분석 비활성화:
	//   --pkg-types os,library : OS 패키지 + 일반 라이브러리만 (Java JAR 제외)
	//   --skip-java-db-update  : Java DB 다운로드 자체 스킵 (866MB+ 절약)
	if c.DisableJavaDB {
		args = append(args,
			"--pkg-types", "os,library",
			"--skip-java-db-update",
		)
	}

	args = append(args, target)

	start := time.Now()

	cmd := exec.CommandContext(scanCtx, c.BinaryPath, args...)
	stdout, err := cmd.Output()
	duration := time.Since(start)

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("trivy scan failed (exit %d): %s: %w",
				exitErr.ExitCode(), string(exitErr.Stderr), err)
		}
		return nil, fmt.Errorf("trivy exec failed: %w", err)
	}

	if !json.Valid(stdout) {
		return nil, fmt.Errorf("trivy returned invalid JSON (len=%d)", len(stdout))
	}

	return &ScanResult{
		Raw:          json.RawMessage(stdout),
		Image:        image,
		Digest:       digest,
		ScanDuration: duration,
	}, nil
}

// stripTag는 "nginx:1.14.0" → "nginx" 처럼 태그 부분을 제거합니다.
// 포트 번호가 있는 레지스트리 URL과 구분합니다 (e.g. "registry.io:5000/img").
func stripTag(image string) string {
	lastSlash := -1
	for i := 0; i < len(image); i++ {
		if image[i] == '/' {
			lastSlash = i
		}
	}
	for i := len(image) - 1; i > lastSlash; i-- {
		if image[i] == ':' {
			return image[:i]
		}
	}
	return image
}

// CheckBinary는 trivy 바이너리가 실행 가능한지 확인합니다.
// 서버 기동 시점에 호출합니다.
func (c *Client) CheckBinary(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, c.BinaryPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy binary check failed: %w (output: %s)", err, string(out))
	}
	return nil
}
