package main

// VARA API client. /api/v1 엔드포인트들에 자산/취약점/노출/evidence를 등록한다.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type APIClient struct {
	base   string
	client *http.Client
}

func NewAPIClient(base string) *APIClient {
	return &APIClient{
		base:   base,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

type Asset struct {
	AssetID        string         `json:"asset_id"`
	AssetType      string         `json:"asset_type"`
	Name           string         `json:"name"`
	Namespace      string         `json:"namespace,omitempty"`
	Cluster        string         `json:"cluster,omitempty"`
	CloudProvider  string         `json:"cloud_provider,omitempty"`
	Image          string         `json:"image,omitempty"`
	ServiceAccount string         `json:"service_account,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type VulnerabilityItem struct {
	CVEID            string  `json:"cve_id"`
	PackageName      string  `json:"package_name"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	Severity         string  `json:"severity"`
	CVSS             float64 `json:"cvss"`
	EPSS             float64 `json:"epss"`
	KEV              bool    `json:"kev"`
	Description      string  `json:"description"`
	PatchStatus      string  `json:"patch_status"`
}

type VulnerabilityRequest struct {
	AssetID         string              `json:"asset_id"`
	Image           string              `json:"image"`
	Scanner         string              `json:"scanner"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type Exposure struct {
	AssetID       string         `json:"asset_id"`
	ExposureLevel string         `json:"exposure_level"`
	ExposureType  string         `json:"exposure_type"`
	Entrypoint    string         `json:"entrypoint"`
	Protocol      string         `json:"protocol,omitempty"`
	Port          int            `json:"port,omitempty"`
	AuthRequired  bool           `json:"auth_required"`
	Description   string         `json:"description,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

type EvidenceGenerateRequest struct {
	AssetID           string   `json:"asset_id"`
	SourceTypes       []string `json:"source_types"`
	GenerateEmbedding bool     `json:"generate_embedding"`
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (a *APIClient) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/api/v1/assets", nil)
		resp, err := a.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("vara-api not reachable at %s", a.base)
}

func (a *APIClient) PostAsset(ctx context.Context, asset Asset) error {
	_, err := a.post(ctx, "/api/v1/assets", asset)
	return err
}

func (a *APIClient) PostVulnerabilities(ctx context.Context, assetID, image string, vulns []VulnerabilityItem) error {
	if len(vulns) == 0 {
		return nil
	}
	_, err := a.post(ctx, "/api/v1/vulnerabilities", VulnerabilityRequest{
		AssetID:         assetID,
		Image:           image,
		Scanner:         "trivy",
		Vulnerabilities: vulns,
	})
	return err
}

func (a *APIClient) PostExposure(ctx context.Context, exp Exposure) error {
	_, err := a.post(ctx, "/api/v1/exposures", exp)
	return err
}

func (a *APIClient) GenerateEvidence(ctx context.Context, assetID string) error {
	_, err := a.post(ctx, "/api/v1/evidence/generate", EvidenceGenerateRequest{
		AssetID:           assetID,
		SourceTypes:       []string{"CVE", "EXPOSURE", "ASSET"},
		GenerateEmbedding: true,
	})
	return err
}

func (a *APIClient) post(ctx context.Context, path string, payload any) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: status=%d body=%s", path, resp.StatusCode, string(raw))
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode envelope from %s: %w", path, err)
	}
	if !env.Success {
		return nil, fmt.Errorf("api error from %s: %s", path, env.Error.Message)
	}
	return env.Data, nil
}
