package main

// Trivy 컨테이너 이미지 스캐너 wrapper.
// trivy 바이너리를 subprocess로 실행해 JSON 결과를 받고,
// VARA의 VulnerabilityItem 슬라이스로 변환한다.
//
// 컨테이너 이미지에는 trivy 바이너리가 함께 패키징되어야 한다 (Dockerfile에서 multi-stage 로 복사).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

type TrivyRunner struct {
	binary string
	seen   map[string][]VulnerabilityItem // 동일 이미지 중복 스캔 방지용 (in-memory)
}

func NewTrivyRunner(binary string) *TrivyRunner {
	if binary == "" {
		binary = "trivy"
	}
	return &TrivyRunner{
		binary: binary,
		seen:   map[string][]VulnerabilityItem{},
	}
}

// trivyReport는 `trivy image --format json` 출력의 부분 구조이다.
// 필요한 필드만 정의해 forward-compatibility 를 확보한다.
type trivyReport struct {
	Results []struct {
		Target          string             `json:"Target"`
		Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVulnerability struct {
	VulnerabilityID  string                  `json:"VulnerabilityID"`
	PkgName          string                  `json:"PkgName"`
	InstalledVersion string                  `json:"InstalledVersion"`
	FixedVersion     string                  `json:"FixedVersion"`
	Severity         string                  `json:"Severity"`
	Description      string                  `json:"Description"`
	Status           string                  `json:"Status"`
	CVSS             map[string]trivyCVSSItem `json:"CVSS"`
}

type trivyCVSSItem struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}

// ScanImage는 단일 이미지를 trivy로 스캔한 뒤 VulnerabilityItem 슬라이스를 반환한다.
// 같은 이미지를 여러 Pod가 사용하는 경우 중복 호출을 피하기 위해 in-memory cache 를 사용한다.
func (t *TrivyRunner) ScanImage(ctx context.Context, image string) ([]VulnerabilityItem, error) {
	if image == "" {
		return nil, nil
	}
	if cached, ok := t.seen[image]; ok {
		return cached, nil
	}

	args := []string{
		"image",
		"--format", "json",
		"--quiet",
		"--scanners", "vuln",
		"--timeout", "10m",
		image,
	}
	cmd := exec.CommandContext(ctx, t.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy %s: %v\nstderr=%s", image, err, stderr.String())
	}

	var report trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("trivy json decode: %w", err)
	}

	out := []VulnerabilityItem{}
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			out = append(out, VulnerabilityItem{
				CVEID:            v.VulnerabilityID,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         v.Severity,
				CVSS:             pickCVSS(v.CVSS),
				EPSS:             0, // trivy 기본 출력에는 EPSS 미포함 — 후속에 enrichment 필요.
				KEV:              false,
				Description:      v.Description,
				PatchStatus:      v.Status,
			})
		}
	}

	t.seen[image] = out
	return out, nil
}

func pickCVSS(m map[string]trivyCVSSItem) float64 {
	// 우선순위: nvd > redhat > 첫 번째 entry.
	if v, ok := m["nvd"]; ok && v.V3Score > 0 {
		return v.V3Score
	}
	if v, ok := m["redhat"]; ok && v.V3Score > 0 {
		return v.V3Score
	}
	for _, v := range m {
		if v.V3Score > 0 {
			return v.V3Score
		}
		if v.V2Score > 0 {
			return v.V2Score
		}
	}
	return 0
}
