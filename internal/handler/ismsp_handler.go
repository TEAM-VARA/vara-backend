package handler

// VARA3 의 ISMS-P 워크플로우 (assets / vulnerabilities / exposures / isms-p controls /
// evidence / vector-search / mappings) 를 그대로 포팅.
//
// 데이터 모델: migrations/002_pgvector.up.sql 의 compliance_* 테이블 + vector(1024)
// 임베딩 백엔드: BGE-M3 FastAPI 서버 (EMBEDDING_SERVER_URL 환경변수)

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ─────────────────────────────────────────────────────────────────
// Request / Response 타입
// ─────────────────────────────────────────────────────────────────

type AssetRequest struct {
	AssetID        string         `json:"asset_id"`
	AssetType      string         `json:"asset_type"`
	Name           string         `json:"name"`
	Namespace      string         `json:"namespace"`
	Cluster        string         `json:"cluster"`
	CloudProvider  string         `json:"cloud_provider"`
	Image          string         `json:"image"`
	ServiceAccount string         `json:"service_account"`
	Metadata       map[string]any `json:"metadata"`
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

type ExposureRequest struct {
	AssetID       string         `json:"asset_id"`
	ExposureLevel string         `json:"exposure_level"`
	ExposureType  string         `json:"exposure_type"`
	Entrypoint    string         `json:"entrypoint"`
	Protocol      string         `json:"protocol"`
	Port          int            `json:"port"`
	AuthRequired  bool           `json:"auth_required"`
	Description   string         `json:"description"`
	Metadata      map[string]any `json:"metadata"`
}

type ISMSControlRequest struct {
	ControlID         string   `json:"control_id"`
	Domain            string   `json:"domain"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Keywords          []string `json:"keywords"`
	GenerateEmbedding bool     `json:"generate_embedding"`
}

type EvidenceGenerateRequest struct {
	AssetID           string   `json:"asset_id"`
	SourceTypes       []string `json:"source_types"`
	GenerateEmbedding bool     `json:"generate_embedding"`
}

type VectorSearchRequest struct {
	ControlID     string   `json:"control_id"`
	TopK          int      `json:"top_k"`
	MinSimilarity float64  `json:"min_similarity"`
	SourceTypes   []string `json:"source_types"`
}

type MappingRunRequest struct {
	ControlID     string   `json:"control_id"`
	TopK          int      `json:"top_k"`
	MinSimilarity float64  `json:"min_similarity"`
	UseRAG        bool     `json:"use_rag"`
	UseRuleEngine bool     `json:"use_rule_engine"`
	SourceTypes   []string `json:"source_types"`
}

type SearchResult struct {
	EvidenceID    int     `json:"evidence_id"`
	SourceType    string  `json:"source_type"`
	AssetID       string  `json:"asset_id"`
	CVEID         string  `json:"cve_id"`
	Severity      string  `json:"severity"`
	ExposureLevel string  `json:"exposure_level"`
	DocumentText  string  `json:"document_text"`
	Similarity    float64 `json:"similarity"`
}

// ─────────────────────────────────────────────────────────────────
// Embedding 클라이언트 (BGE-M3 FastAPI 서버)
// ─────────────────────────────────────────────────────────────────

type EmbeddingClient struct {
	Model  string
	URL    string
	Client *http.Client
}

type LocalEmbeddingRequest struct {
	Text string `json:"text"`
}

type LocalEmbeddingResponse struct {
	Model     string    `json:"model"`
	Dimension int       `json:"dimension"`
	Embedding []float64 `json:"embedding"`
}

func NewEmbeddingClient() *EmbeddingClient {
	return &EmbeddingClient{
		Model: "BAAI/bge-m3",
		URL:   envOr("EMBEDDING_SERVER_URL", "http://localhost:9000/embed"),
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *EmbeddingClient) CreateEmbedding(text string) ([]float64, error) {
	bodyBytes, err := json.Marshal(LocalEmbeddingRequest{Text: text})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.URL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding server failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var result LocalEmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Embedding) == 0 {
		return nil, fmt.Errorf("embedding response is empty")
	}
	return result.Embedding, nil
}

// ─────────────────────────────────────────────────────────────────
// ISMSPHandler — 모든 컴플라이언스 핸들러를 모아둔 컨테이너
// ─────────────────────────────────────────────────────────────────

type ISMSPHandler struct {
	pg        *pgxpool.Pool
	embedding *EmbeddingClient
}

func NewISMSP(pg *pgxpool.Pool) *ISMSPHandler {
	return &ISMSPHandler{
		pg:        pg,
		embedding: NewEmbeddingClient(),
	}
}

func ismspSuccess(c *gin.Context, data any, message string) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data, "message": message})
}

func ismspFail(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{"success": false, "error": gin.H{"message": message}})
}

// ─────────────────────────────────────────────────────────────────
// Asset
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) CreateAsset(c *gin.Context) {
	var req AssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}
	if req.AssetID == "" || req.AssetType == "" || req.Name == "" {
		ismspFail(c, http.StatusBadRequest, "asset_id, asset_type, name are required")
		return
	}

	metaBytes, _ := json.Marshal(req.Metadata)

	_, err := h.pg.Exec(c.Request.Context(), `
		INSERT INTO compliance_assets (
			asset_id, asset_type, name, namespace, cluster_name,
			cloud_provider, image, service_account, metadata
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (asset_id)
		DO UPDATE SET
			asset_type = EXCLUDED.asset_type,
			name = EXCLUDED.name,
			namespace = EXCLUDED.namespace,
			cluster_name = EXCLUDED.cluster_name,
			cloud_provider = EXCLUDED.cloud_provider,
			image = EXCLUDED.image,
			service_account = EXCLUDED.service_account,
			metadata = EXCLUDED.metadata
	`,
		req.AssetID, req.AssetType, req.Name, req.Namespace, req.Cluster,
		req.CloudProvider, req.Image, req.ServiceAccount, metaBytes,
	)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	ismspSuccess(c, gin.H{"asset_id": req.AssetID, "status": "CREATED"}, "asset created")
}

func (h *ISMSPHandler) ListAssets(c *gin.Context) {
	rows, err := h.pg.Query(c.Request.Context(), `
		SELECT asset_id, asset_type, name, namespace, cluster_name, cloud_provider, image, service_account
		FROM compliance_assets
		ORDER BY id DESC
		LIMIT 100
	`)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}
	for rows.Next() {
		var assetID, assetType, name string
		var namespace, cluster, provider, image, serviceAccount *string
		if err := rows.Scan(&assetID, &assetType, &name, &namespace, &cluster, &provider, &image, &serviceAccount); err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, gin.H{
			"asset_id": assetID, "asset_type": assetType, "name": name,
			"namespace": namespace, "cluster": cluster, "cloud_provider": provider,
			"image": image, "service_account": serviceAccount,
		})
	}
	ismspSuccess(c, gin.H{"items": items}, "success")
}

func (h *ISMSPHandler) GetAsset(c *gin.Context) {
	assetID := c.Param("asset_id")

	var assetType, name string
	var namespace, cluster, provider, image, serviceAccount *string

	err := h.pg.QueryRow(c.Request.Context(), `
		SELECT asset_type, name, namespace, cluster_name, cloud_provider, image, service_account
		FROM compliance_assets
		WHERE asset_id = $1
	`, assetID).Scan(&assetType, &name, &namespace, &cluster, &provider, &image, &serviceAccount)
	if err != nil {
		ismspFail(c, http.StatusNotFound, "asset not found")
		return
	}

	ismspSuccess(c, gin.H{
		"asset_id": assetID, "asset_type": assetType, "name": name,
		"namespace": namespace, "cluster": cluster, "cloud_provider": provider,
		"image": image, "service_account": serviceAccount,
	}, "success")
}

// ─────────────────────────────────────────────────────────────────
// Vulnerability (CVE)
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) CreateVulnerabilities(c *gin.Context) {
	var req VulnerabilityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}

	count := 0
	for _, v := range req.Vulnerabilities {
		_, err := h.pg.Exec(c.Request.Context(), `
			INSERT INTO compliance_vulnerabilities (
				asset_id, image, scanner, cve_id, package_name,
				installed_version, fixed_version, severity, cvss, epss,
				kev, description, patch_status
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		`,
			req.AssetID, req.Image, req.Scanner, v.CVEID, v.PackageName,
			v.InstalledVersion, v.FixedVersion, v.Severity, v.CVSS, v.EPSS,
			v.KEV, v.Description, v.PatchStatus,
		)
		if err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		count++
	}
	ismspSuccess(c, gin.H{"asset_id": req.AssetID, "inserted_count": count}, "vulnerabilities saved")
}

func (h *ISMSPHandler) ListAssetVulnerabilities(c *gin.Context) {
	assetID := c.Param("asset_id")

	rows, err := h.pg.Query(c.Request.Context(), `
		SELECT cve_id, package_name, severity, cvss, epss, kev, patch_status, description
		FROM compliance_vulnerabilities
		WHERE asset_id = $1
		ORDER BY cvss DESC NULLS LAST
	`, assetID)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}
	for rows.Next() {
		var cveID, packageName, severity, patchStatus, description *string
		var cvss, epss *float64
		var kev *bool
		if err := rows.Scan(&cveID, &packageName, &severity, &cvss, &epss, &kev, &patchStatus, &description); err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, gin.H{
			"cve_id": cveID, "package_name": packageName, "severity": severity,
			"cvss": cvss, "epss": epss, "kev": kev,
			"patch_status": patchStatus, "description": description,
		})
	}
	ismspSuccess(c, gin.H{"asset_id": assetID, "vulnerabilities": items}, "success")
}

// ─────────────────────────────────────────────────────────────────
// Exposure
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) CreateExposure(c *gin.Context) {
	var req ExposureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}
	metaBytes, _ := json.Marshal(req.Metadata)

	_, err := h.pg.Exec(c.Request.Context(), `
		INSERT INTO compliance_exposures (
			asset_id, exposure_level, exposure_type, entrypoint,
			protocol, port, auth_required, description, metadata
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		req.AssetID, req.ExposureLevel, req.ExposureType, req.Entrypoint,
		req.Protocol, req.Port, req.AuthRequired, req.Description, metaBytes,
	)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	ismspSuccess(c, gin.H{
		"asset_id": req.AssetID, "exposure_level": req.ExposureLevel,
		"exposure_type": req.ExposureType, "exposure_status": "CREATED",
	}, "exposure saved")
}

func (h *ISMSPHandler) ListExposures(c *gin.Context) {
	level := c.Query("level")

	query := `
		SELECT asset_id, exposure_level, exposure_type, entrypoint, protocol, port, auth_required, description
		FROM compliance_exposures
	`
	args := []any{}
	if level != "" {
		query += ` WHERE exposure_level = $1`
		args = append(args, level)
	}
	query += ` ORDER BY id DESC LIMIT 100`

	rows, err := h.pg.Query(c.Request.Context(), query, args...)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}
	for rows.Next() {
		var assetID, exposureLevel string
		var exposureType, entrypoint, protocol, description *string
		var port *int
		var authRequired *bool
		if err := rows.Scan(&assetID, &exposureLevel, &exposureType, &entrypoint, &protocol, &port, &authRequired, &description); err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, gin.H{
			"asset_id": assetID, "exposure_level": exposureLevel, "exposure_type": exposureType,
			"entrypoint": entrypoint, "protocol": protocol, "port": port,
			"auth_required": authRequired, "description": description,
		})
	}
	ismspSuccess(c, gin.H{"items": items}, "success")
}

// ─────────────────────────────────────────────────────────────────
// ISMS-P 통제항목
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) CreateISMSControl(c *gin.Context) {
	var req ISMSControlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}

	text := buildISMSControlEmbeddingText(req)

	embedding, err := h.embedding.CreateEmbedding(text)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	vector := toPgVector(embedding)

	_, err = h.pg.Exec(c.Request.Context(), `
		INSERT INTO compliance_isms_p_controls (
			control_id, domain, title, description, keywords, embedding
		)
		VALUES ($1,$2,$3,$4,$5,$6::vector)
		ON CONFLICT (control_id)
		DO UPDATE SET
			domain = EXCLUDED.domain,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			keywords = EXCLUDED.keywords,
			embedding = EXCLUDED.embedding
	`,
		req.ControlID, req.Domain, req.Title, req.Description, req.Keywords, vector,
	)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	ismspSuccess(c, gin.H{"control_id": req.ControlID, "embedding_status": "CREATED"}, "isms-p control created")
}

func (h *ISMSPHandler) ListISMSControls(c *gin.Context) {
	rows, err := h.pg.Query(c.Request.Context(), `
		SELECT control_id, domain, title, description, keywords
		FROM compliance_isms_p_controls
		ORDER BY control_id
		LIMIT 100
	`)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}
	for rows.Next() {
		var controlID, title string
		var domain, description *string
		var keywords []string
		if err := rows.Scan(&controlID, &domain, &title, &description, &keywords); err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, gin.H{
			"control_id": controlID, "domain": domain, "title": title,
			"description": description, "keywords": keywords,
		})
	}
	ismspSuccess(c, gin.H{"items": items}, "success")
}

func (h *ISMSPHandler) GetISMSControl(c *gin.Context) {
	controlID := c.Param("control_id")

	var domain, description *string
	var title string
	var keywords []string

	err := h.pg.QueryRow(c.Request.Context(), `
		SELECT domain, title, description, keywords
		FROM compliance_isms_p_controls
		WHERE control_id = $1
	`, controlID).Scan(&domain, &title, &description, &keywords)
	if err != nil {
		ismspFail(c, http.StatusNotFound, "control not found")
		return
	}

	ismspSuccess(c, gin.H{
		"control_id": controlID, "domain": domain, "title": title,
		"description": description, "keywords": keywords,
	}, "success")
}

// ─────────────────────────────────────────────────────────────────
// Evidence 생성/조회
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) GenerateEvidence(c *gin.Context) {
	var req EvidenceGenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}

	sourceSet := map[string]bool{}
	for _, s := range req.SourceTypes {
		sourceSet[strings.ToUpper(s)] = true
	}

	evidenceIDs := []int{}
	if len(sourceSet) == 0 || sourceSet["CVE"] {
		ids, err := h.generateCVEEvidence(c.Request.Context(), req.AssetID)
		if err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		evidenceIDs = append(evidenceIDs, ids...)
	}
	if len(sourceSet) == 0 || sourceSet["EXPOSURE"] {
		ids, err := h.generateExposureEvidence(c.Request.Context(), req.AssetID)
		if err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		evidenceIDs = append(evidenceIDs, ids...)
	}
	if len(sourceSet) == 0 || sourceSet["ASSET"] {
		ids, err := h.generateAssetEvidence(c.Request.Context(), req.AssetID)
		if err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		evidenceIDs = append(evidenceIDs, ids...)
	}

	ismspSuccess(c, gin.H{
		"asset_id":        req.AssetID,
		"generated_count": len(evidenceIDs),
		"evidence_ids":    evidenceIDs,
	}, "evidence generated")
}

func (h *ISMSPHandler) generateCVEEvidence(ctx context.Context, assetID string) ([]int, error) {
	rows, err := h.pg.Query(ctx, `
		SELECT cve_id, severity, cvss, epss, kev, description, patch_status
		FROM compliance_vulnerabilities
		WHERE asset_id = $1
	`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := []int{}
	for rows.Next() {
		var cveID, severity, description, patchStatus *string
		var cvss, epss *float64
		var kev *bool
		if err := rows.Scan(&cveID, &severity, &cvss, &epss, &kev, &description, &patchStatus); err != nil {
			return nil, err
		}

		text := fmt.Sprintf(
			"자산 %s에서 %s 취약점이 발견되었다. 심각도는 %s이고 CVSS는 %.1f, EPSS는 %.2f이다. KEV 포함 여부는 %t이다. 패치 상태는 %s이다. 설명: %s",
			assetID, valueString(cveID), valueString(severity),
			valueFloat(cvss), valueFloat(epss), valueBool(kev),
			valueString(patchStatus), valueString(description),
		)

		embedding, err := h.embedding.CreateEmbedding(text)
		if err != nil {
			return nil, err
		}
		vector := toPgVector(embedding)

		var id int
		err = h.pg.QueryRow(ctx, `
			INSERT INTO compliance_evidence_documents (
				source_type, asset_id, cve_id, severity, document_text, embedding
			)
			VALUES ('CVE', $1, $2, $3, $4, $5::vector)
			RETURNING id
		`, assetID, valueString(cveID), valueString(severity), text, vector).Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (h *ISMSPHandler) generateExposureEvidence(ctx context.Context, assetID string) ([]int, error) {
	rows, err := h.pg.Query(ctx, `
		SELECT exposure_level, exposure_type, entrypoint, protocol, port, auth_required, description
		FROM compliance_exposures
		WHERE asset_id = $1
	`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := []int{}
	for rows.Next() {
		var exposureLevel string
		var exposureType, entrypoint, protocol, description *string
		var port *int
		var authRequired *bool
		if err := rows.Scan(&exposureLevel, &exposureType, &entrypoint, &protocol, &port, &authRequired, &description); err != nil {
			return nil, err
		}

		text := fmt.Sprintf(
			"자산 %s는 노출 등급 %s에 해당한다. 노출 유형은 %s이고 진입점은 %s, 프로토콜은 %s, 포트는 %d이다. 인증 필요 여부는 %t이다. 설명: %s",
			assetID, exposureLevel, valueString(exposureType),
			valueString(entrypoint), valueString(protocol), valueInt(port),
			valueBool(authRequired), valueString(description),
		)

		embedding, err := h.embedding.CreateEmbedding(text)
		if err != nil {
			return nil, err
		}
		vector := toPgVector(embedding)

		var id int
		err = h.pg.QueryRow(ctx, `
			INSERT INTO compliance_evidence_documents (
				source_type, asset_id, exposure_level, document_text, embedding
			)
			VALUES ('EXPOSURE', $1, $2, $3, $4::vector)
			RETURNING id
		`, assetID, exposureLevel, text, vector).Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (h *ISMSPHandler) generateAssetEvidence(ctx context.Context, assetID string) ([]int, error) {
	rows, err := h.pg.Query(ctx, `
		SELECT asset_id, asset_type, name, namespace, cluster_name,
		       cloud_provider, image, service_account, metadata
		FROM compliance_assets
		WHERE ($1 = '' OR asset_id = $1)
	`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := []int{}
	for rows.Next() {
		var aid, atype, name string
		var namespace, cluster, provider, image, sa *string
		var metadataBytes []byte
		if err := rows.Scan(&aid, &atype, &name, &namespace, &cluster, &provider, &image, &sa, &metadataBytes); err != nil {
			return nil, err
		}

		var metadata map[string]any
		if len(metadataBytes) > 0 {
			_ = json.Unmarshal(metadataBytes, &metadata)
		}

		text := buildAssetEvidenceText(
			aid, atype, name,
			valueString(namespace), valueString(cluster), valueString(provider),
			valueString(image), valueString(sa), metadata,
		)

		embedding, err := h.embedding.CreateEmbedding(text)
		if err != nil {
			return nil, err
		}
		vector := toPgVector(embedding)

		metaOut, _ := json.Marshal(metadata)

		var id int
		err = h.pg.QueryRow(ctx, `
			INSERT INTO compliance_evidence_documents (
				source_type, asset_id, namespace, document_text, metadata, embedding
			)
			VALUES ('ASSET', $1, $2, $3, $4, $5::vector)
			RETURNING id
		`, aid, valueString(namespace), text, metaOut, vector).Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (h *ISMSPHandler) ListEvidence(c *gin.Context) {
	rows, err := h.pg.Query(c.Request.Context(), `
		SELECT id, source_type, asset_id, cve_id, severity, exposure_level, document_text
		FROM compliance_evidence_documents
		ORDER BY id DESC
		LIMIT 100
	`)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}
	for rows.Next() {
		var id int
		var sourceType, documentText string
		var assetID, cveID, severity, exposureLevel *string
		if err := rows.Scan(&id, &sourceType, &assetID, &cveID, &severity, &exposureLevel, &documentText); err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, gin.H{
			"evidence_id": id, "source_type": sourceType, "asset_id": assetID,
			"cve_id": cveID, "severity": severity, "exposure_level": exposureLevel,
			"document_text": documentText,
		})
	}
	ismspSuccess(c, gin.H{"items": items}, "success")
}

// ─────────────────────────────────────────────────────────────────
// 벡터 검색 / 매핑
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) VectorSearchISMSP(c *gin.Context) {
	var req VectorSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}
	if req.TopK <= 0 {
		req.TopK = 10
	}
	if req.MinSimilarity <= 0 {
		req.MinSimilarity = 0.5
	}

	controlText, err := h.getControlSearchText(c.Request.Context(), req.ControlID)
	if err != nil {
		ismspFail(c, http.StatusNotFound, "control not found")
		return
	}

	results, err := h.searchEvidenceByText(c.Request.Context(), controlText, req.TopK, req.MinSimilarity, req.SourceTypes)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}

	ismspSuccess(c, gin.H{
		"control_id": req.ControlID,
		"query_text": controlText,
		"results":    results,
	}, "vector search completed")
}

func (h *ISMSPHandler) RunMapping(c *gin.Context) {
	var req MappingRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ismspFail(c, http.StatusBadRequest, err.Error())
		return
	}
	if req.TopK <= 0 {
		req.TopK = 10
	}
	if req.MinSimilarity <= 0 {
		req.MinSimilarity = 0.5
	}

	controlText, err := h.getControlSearchText(c.Request.Context(), req.ControlID)
	if err != nil {
		ismspFail(c, http.StatusNotFound, "control not found")
		return
	}

	results, err := h.searchEvidenceByText(c.Request.Context(), controlText, req.TopK, req.MinSimilarity, req.SourceTypes)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}

	status, riskLevel, riskScore, summary, reason, recommendations := judgeMapping(results)

	evidenceIDs := []int{}
	for _, r := range results {
		evidenceIDs = append(evidenceIDs, r.EvidenceID)
	}

	var mappingID int
	err = h.pg.QueryRow(c.Request.Context(), `
		INSERT INTO compliance_isms_p_mappings (
			control_id, status, risk_level, risk_score, summary, reason, recommendations, evidence_ids
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id
	`, req.ControlID, status, riskLevel, riskScore, summary, reason, recommendations, evidenceIDs).Scan(&mappingID)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}

	ismspSuccess(c, gin.H{
		"mapping_id":      mappingID,
		"control_id":      req.ControlID,
		"status":          status,
		"risk_level":      riskLevel,
		"risk_score":      riskScore,
		"summary":         summary,
		"reason":          reason,
		"recommendations": recommendations,
		"evidence":        results,
	}, "isms-p mapping completed")
}

func (h *ISMSPHandler) ListMappings(c *gin.Context) {
	rows, err := h.pg.Query(c.Request.Context(), `
		SELECT id, control_id, status, risk_level, risk_score, summary, created_at
		FROM compliance_isms_p_mappings
		ORDER BY id DESC
		LIMIT 100
	`)
	if err != nil {
		ismspFail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}
	for rows.Next() {
		var id int
		var controlID, status, riskLevel, summary string
		var riskScore float64
		var createdAt time.Time
		if err := rows.Scan(&id, &controlID, &status, &riskLevel, &riskScore, &summary, &createdAt); err != nil {
			ismspFail(c, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, gin.H{
			"mapping_id": id, "control_id": controlID, "status": status,
			"risk_level": riskLevel, "risk_score": riskScore,
			"summary": summary, "created_at": createdAt,
		})
	}
	ismspSuccess(c, gin.H{"items": items}, "success")
}

func (h *ISMSPHandler) GetMapping(c *gin.Context) {
	mappingID := c.Param("mapping_id")

	var id int
	var controlID, status, riskLevel, summary, reason string
	var riskScore float64
	var recommendations []string
	var evidenceIDs []int
	var createdAt time.Time

	err := h.pg.QueryRow(c.Request.Context(), `
		SELECT id, control_id, status, risk_level, risk_score, summary, reason, recommendations, evidence_ids, created_at
		FROM compliance_isms_p_mappings
		WHERE id = $1
	`, mappingID).Scan(&id, &controlID, &status, &riskLevel, &riskScore, &summary, &reason, &recommendations, &evidenceIDs, &createdAt)
	if err != nil {
		ismspFail(c, http.StatusNotFound, "mapping not found")
		return
	}

	ismspSuccess(c, gin.H{
		"mapping_id": id, "control_id": controlID, "status": status,
		"risk_level": riskLevel, "risk_score": riskScore,
		"summary": summary, "reason": reason,
		"recommendations": recommendations, "evidence_ids": evidenceIDs,
		"created_at": createdAt,
	}, "success")
}

// ─────────────────────────────────────────────────────────────────
// 검색 / 룰 엔진 / 텍스트 빌더
// ─────────────────────────────────────────────────────────────────

func (h *ISMSPHandler) getControlSearchText(ctx context.Context, controlID string) (string, error) {
	var domain, description *string
	var title string
	var keywords []string

	err := h.pg.QueryRow(ctx, `
		SELECT domain, title, description, keywords
		FROM compliance_isms_p_controls
		WHERE control_id = $1
	`, controlID).Scan(&domain, &title, &description, &keywords)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"ISMS-P 항목 %s. 분류: %s. 제목: %s. 설명: %s. 관련 키워드: %s.",
		controlID, valueString(domain), title, valueString(description), strings.Join(keywords, ", "),
	), nil
}

func (h *ISMSPHandler) searchEvidenceByText(
	ctx context.Context,
	queryText string,
	topK int,
	minSimilarity float64,
	sourceTypes []string,
) ([]SearchResult, error) {
	queryEmbedding, err := h.embedding.CreateEmbedding(queryText)
	if err != nil {
		return nil, err
	}
	vector := toPgVector(queryEmbedding)

	rows, err := h.pg.Query(ctx, `
		SELECT
			id, source_type, asset_id, cve_id, severity, exposure_level, document_text,
			1 - (embedding <=> $1::vector) AS similarity
		FROM compliance_evidence_documents
		ORDER BY embedding <=> $1::vector
		LIMIT $2
	`, vector, topK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sourceFilter := map[string]bool{}
	for _, s := range sourceTypes {
		sourceFilter[strings.ToUpper(s)] = true
	}

	results := []SearchResult{}
	for rows.Next() {
		var r SearchResult
		var assetID, cveID, severity, exposureLevel *string
		err := rows.Scan(
			&r.EvidenceID, &r.SourceType, &assetID, &cveID, &severity,
			&exposureLevel, &r.DocumentText, &r.Similarity,
		)
		if err != nil {
			return nil, err
		}
		r.AssetID = valueString(assetID)
		r.CVEID = valueString(cveID)
		r.Severity = valueString(severity)
		r.ExposureLevel = valueString(exposureLevel)

		if len(sourceFilter) > 0 && !sourceFilter[strings.ToUpper(r.SourceType)] {
			continue
		}
		if r.Similarity >= minSimilarity {
			results = append(results, r)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Similarity > results[j].Similarity
	})
	return results, nil
}

func judgeMapping(results []SearchResult) (
	status, riskLevel string, riskScore float64,
	summary, reason string, recommendations []string,
) {
	if len(results) == 0 {
		return "UNKNOWN", "LOW", 0.0,
			"관련 evidence가 부족하여 판단할 수 없다.",
			"ISMS-P 항목과 직접 연결되는 자산, 취약점, 노출 근거가 검색되지 않았다.",
			[]string{"관련 자산, 취약점, 노출도 evidence를 추가 수집한다."}
	}

	maxSim := 0.0
	hasCritical, hasHigh, hasExposure, hasE4, hasCVE := false, false, false, false, false

	for _, r := range results {
		if r.Similarity > maxSim {
			maxSim = r.Similarity
		}
		if strings.EqualFold(r.SourceType, "CVE") {
			hasCVE = true
		}
		if strings.EqualFold(r.Severity, "CRITICAL") {
			hasCritical = true
		}
		if strings.EqualFold(r.Severity, "HIGH") {
			hasHigh = true
		}
		if strings.EqualFold(r.SourceType, "EXPOSURE") {
			hasExposure = true
		}
		if strings.EqualFold(r.ExposureLevel, "E4") {
			hasE4 = true
		}
	}

	score := maxSim * 0.45
	if hasCritical {
		score += 0.25
	} else if hasHigh {
		score += 0.15
	}
	if hasExposure {
		score += 0.15
	}
	if hasE4 {
		score += 0.15
	}
	if score > 1.0 {
		score = 1.0
	}

	switch {
	case score >= 0.85:
		riskLevel = "CRITICAL"
	case score >= 0.70:
		riskLevel = "HIGH"
	case score >= 0.45:
		riskLevel = "MEDIUM"
	default:
		riskLevel = "LOW"
	}

	switch {
	case hasCVE && hasExposure && score >= 0.70:
		status = "NON_COMPLIANT"
		summary = "취약점 evidence와 외부 노출 evidence가 함께 확인되어 미준수 가능성이 높다."
		reason = "검색된 evidence에서 취약점과 외부 노출 근거가 동시에 발견되었다. 운영 자산이 외부에 노출되어 있고 고위험 취약점이 존재하는 경우 ISMS-P 취약점 관리 및 보안관리 항목에서 미흡으로 판단할 수 있다."
		recommendations = []string{
			"취약 패키지를 fixed version으로 업데이트한다.",
			"패치 전까지 public ingress 또는 외부 접근 경로를 제한한다.",
			"조치 완료 후 재스캔 결과를 evidence로 저장한다.",
		}
	case score >= 0.45:
		status = "NEEDS_REVIEW"
		summary = "관련 evidence는 존재하지만 미준수로 단정하기에는 추가 확인이 필요하다."
		reason = "검색된 evidence의 유사도는 의미가 있으나, 취약점 조치 여부, 외부 노출 여부, 운영 영향도 중 일부 근거가 부족하다."
		recommendations = []string{
			"패치 상태, 외부 노출 상태, 접근 권한 정보를 추가 확인한다.",
			"관련 evidence를 보완한 뒤 매핑을 재실행한다.",
		}
	default:
		status = "COMPLIANT"
		summary = "현재 evidence 기준으로 명확한 미준수 근거는 확인되지 않았다."
		reason = "검색된 evidence의 위험도가 낮거나 ISMS-P 항목과의 직접 관련성이 낮다."
		recommendations = []string{
			"정기적으로 취약점 스캔과 evidence 갱신을 수행한다.",
		}
	}

	return status, riskLevel, round(score), summary, reason, recommendations
}

func buildISMSControlEmbeddingText(req ISMSControlRequest) string {
	return fmt.Sprintf(
		"ISMS-P 항목 %s. 분류: %s. 제목: %s. 설명: %s. 관련 키워드: %s.",
		req.ControlID, req.Domain, req.Title, req.Description, strings.Join(req.Keywords, ", "),
	)
}

func buildAssetEvidenceText(
	assetID, assetType, name, namespace, cluster, cloudProvider, image, serviceAccount string,
	metadata map[string]any,
) string {
	switch strings.ToLower(assetType) {
	case "pod":
		return buildPodEvidenceText(assetID, name, namespace, cluster, cloudProvider, image, serviceAccount, metadata)
	case "rds":
		return buildRDSEvidenceText(assetID, name, cluster, metadata)
	default:
		return buildGenericAssetEvidenceText(assetID, assetType, name, namespace, cluster, cloudProvider, image, serviceAccount)
	}
}

func buildPodEvidenceText(
	assetID, name, namespace, cluster, cloudProvider, image, serviceAccount string,
	metadata map[string]any,
) string {
	privileged := metaBool(metadata, "privileged")
	hostNetwork := metaBool(metadata, "host_network")

	base := fmt.Sprintf(
		"자산 %s 는 cloud_provider=%s 클러스터 %s 의 namespace %s 에 배포된 Pod %s 이다. "+
			"컨테이너 이미지는 %s 이고 ServiceAccount 는 %s 이다. "+
			"보안 컨텍스트: privileged=%t, hostNetwork=%t.",
		assetID, valueOrDash(cloudProvider), valueOrDash(cluster),
		valueOrDash(namespace), name, valueOrDash(image),
		valueOrDash(serviceAccount), privileged, hostNetwork,
	)

	concerns := []string{}
	if privileged {
		concerns = append(concerns,
			"이 Pod 는 privileged=true 로 실행되어 호스트 자원에 과도한 접근 권한을 가지며 특수 권한 계정 통제 관점에서 위험하다.")
	}
	if hostNetwork {
		concerns = append(concerns,
			"hostNetwork=true 로 호스트 네트워크 네임스페이스를 공유하여 네트워크 영역 분리가 적용되지 않는다.")
	}
	if serviceAccount == "" || strings.EqualFold(serviceAccount, "default") {
		concerns = append(concerns,
			"ServiceAccount 가 default 로 설정되어 사용자 계정 분리 및 최소 권한 원칙이 적용되지 않았다.")
	}
	if isUnpinnedTag(image) {
		concerns = append(concerns,
			"컨테이너 이미지 태그가 명시되지 않았거나 latest 로 고정되어 있어 패치 버전 추적과 변경 관리가 어렵다.")
	}
	if len(concerns) > 0 {
		base += " 보안 우려: " + strings.Join(concerns, " ")
	}
	return base
}

func buildRDSEvidenceText(assetID, name, cluster string, metadata map[string]any) string {
	engine := metaString(metadata, "engine")
	version := metaString(metadata, "engine_version")
	class := metaString(metadata, "instance_class")
	pubAccess := metaBool(metadata, "publicly_accessible")
	encrypted := metaBool(metadata, "storage_encrypted")
	iamAuth := metaBool(metadata, "iam_db_auth_enabled")
	multiAZ := metaBool(metadata, "multi_az")
	delProt := metaBool(metadata, "deletion_protection")
	backupDays := metaInt(metadata, "backup_retention_period_days")

	base := fmt.Sprintf(
		"자산 %s 는 cluster=%s 에 연관된 AWS RDS 인스턴스 %s 이다. "+
			"엔진은 %s %s, 인스턴스 클래스는 %s 이다. "+
			"publicly_accessible=%t, storage_encrypted=%t, iam_db_auth_enabled=%t, "+
			"multi_az=%t, deletion_protection=%t, backup_retention_period_days=%d.",
		assetID, valueOrDash(cluster), name,
		valueOrDash(engine), valueOrDash(version), valueOrDash(class),
		pubAccess, encrypted, iamAuth, multiAZ, delProt, backupDays,
	)

	concerns := []string{}
	if pubAccess {
		concerns = append(concerns, "PubliclyAccessible=true 로 인터넷 경로에서 데이터베이스 endpoint 에 도달 가능하다.")
	}
	if !encrypted {
		concerns = append(concerns, "StorageEncrypted=false 로 저장 데이터가 KMS 기반으로 암호화되지 않아 암호정책 적용이 미흡하다.")
	}
	if !iamAuth {
		concerns = append(concerns, "IAMDatabaseAuthenticationEnabled=false 로 IAM 기반 DB 인증이 적용되지 않아 비밀번호 기반 인증에만 의존한다.")
	}
	if !multiAZ {
		concerns = append(concerns, "MultiAZ=false 로 단일 가용영역에서 운영되어 가용성 및 재해복구 요건 충족이 어렵다.")
	}
	if !delProt {
		concerns = append(concerns, "DeletionProtection=false 로 인스턴스 삭제 보호가 활성화되어 있지 않다.")
	}
	if backupDays == 0 {
		concerns = append(concerns, "BackupRetentionPeriod=0 으로 자동 백업이 비활성화되어 백업 및 복구관리가 미흡하다.")
	}
	if len(concerns) > 0 {
		base += " 보안 및 가용성 우려: " + strings.Join(concerns, " ")
	}
	return base
}

func buildGenericAssetEvidenceText(
	assetID, assetType, name, namespace, cluster, cloudProvider, image, serviceAccount string,
) string {
	return fmt.Sprintf(
		"자산 %s 는 cloud_provider=%s 클러스터 %s 의 %s 자산 %s 이다. "+
			"namespace=%s, image=%s, service_account=%s.",
		assetID, valueOrDash(cloudProvider), valueOrDash(cluster),
		assetType, name, valueOrDash(namespace), valueOrDash(image), valueOrDash(serviceAccount),
	)
}

// ─────────────────────────────────────────────────────────────────
// 순수 헬퍼들
// ─────────────────────────────────────────────────────────────────

func toPgVector(vec []float64) string {
	parts := make([]string, len(vec))
	for i, v := range vec {
		parts[i] = fmt.Sprintf("%.8f", v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func valueString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func valueFloat(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}
func valueBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}
func valueInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}
func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
func round(v float64) float64 { return math.Round(v*100) / 100 }

func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
func metaBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
func metaInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

func isUnpinnedTag(image string) bool {
	if image == "" {
		return true
	}
	if strings.Contains(image, ":latest") {
		return true
	}
	lastSlash := strings.LastIndex(image, "/")
	last := image[lastSlash+1:]
	return !strings.Contains(last, ":")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
