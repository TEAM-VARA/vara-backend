package main

// 이 파일은 Cloud/Kubernetes 자산, CVE, 노출도 정보를 수집하고,
// 이를 ISMS-P 통제항목과 pgvector 기반 유사도 검색으로 매핑하는 MVP 백엔드입니다.
// 주요 흐름: 자산 등록 → 취약점/노출도 등록 → Evidence 생성 → 벡터 검색 → ISMS-P 매핑 판단.

import (
	// 표준 라이브러리: HTTP 요청, JSON 처리, 로깅, 문자열/수학 처리 등에 사용
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	// Gin: REST API 라우팅 및 HTTP 핸들러 구성
	"github.com/gin-gonic/gin"
	// pgxpool: PostgreSQL 커넥션 풀 관리
	"github.com/jackc/pgx/v5/pgxpool"
)

// db는 애플리케이션 전체에서 공유하는 PostgreSQL 커넥션 풀입니다.
var db *pgxpool.Pool

// embeddingClient는 ISMS-P 항목과 Evidence 문장을 OpenAI embedding vector로 변환할 때 사용합니다.
var embeddingClient *EmbeddingClient

// AssetRequest는 /assets API에서 받는 자산 등록 요청 구조체입니다.
// Kubernetes Pod, 이미지, ServiceAccount, 클러스터 정보 등을 저장합니다.
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

// VulnerabilityItem은 하나의 CVE/취약점 정보를 표현합니다.
// Trivy 결과의 각 vulnerability 항목에 대응됩니다.
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

// VulnerabilityRequest는 하나의 자산에 여러 취약점을 등록할 때 사용하는 요청 구조체입니다.
type VulnerabilityRequest struct {
	AssetID         string              `json:"asset_id"`
	Image           string              `json:"image"`
	Scanner         string              `json:"scanner"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

// ExposureRequest는 자산의 외부 노출 정보를 등록할 때 사용하는 요청 구조체입니다.
// 예: Public Ingress, LoadBalancer, 공개 endpoint 등.
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

// ISMSControlRequest는 ISMS-P 통제항목을 등록할 때 사용하는 요청 구조체입니다.
// title, description, keywords를 합쳐 embedding을 생성합니다.
type ISMSControlRequest struct {
	ControlID         string   `json:"control_id"`
	Domain            string   `json:"domain"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Keywords          []string `json:"keywords"`
	GenerateEmbedding bool     `json:"generate_embedding"`
}

// EvidenceGenerateRequest는 기존 CVE/노출도 데이터를 문장형 Evidence로 변환할 때 사용합니다.
type EvidenceGenerateRequest struct {
	AssetID           string   `json:"asset_id"`
	SourceTypes       []string `json:"source_types"`
	GenerateEmbedding bool     `json:"generate_embedding"`
}

// VectorSearchRequest는 특정 ISMS-P 항목 기준으로 관련 Evidence를 벡터 검색할 때 사용합니다.
type VectorSearchRequest struct {
	ControlID     string   `json:"control_id"`
	TopK          int      `json:"top_k"`
	MinSimilarity float64  `json:"min_similarity"`
	SourceTypes   []string `json:"source_types"`
}

// MappingRunRequest는 ISMS-P 매핑 실행 요청 구조체입니다.
// 내부적으로 vector search 후 rule 기반 판단을 수행합니다.
type MappingRunRequest struct {
	ControlID     string   `json:"control_id"`
	TopK          int      `json:"top_k"`
	MinSimilarity float64  `json:"min_similarity"`
	UseRAG        bool     `json:"use_rag"`
	UseRuleEngine bool     `json:"use_rule_engine"`
	SourceTypes   []string `json:"source_types"`
}

// SearchResult는 pgvector 유사도 검색 결과를 API 응답으로 반환하기 위한 구조체입니다.
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

// main은 DB 연결, EmbeddingClient 초기화, Gin 라우터 등록, 서버 실행을 담당합니다.
func main() {
	ctx := context.Background()

	// DSN 은 vara-backend 의 config 컨벤션과 동일하게 POSTGRES_* env 6개로부터 조립한다.
	// 같은 RDS 인스턴스를 공유하더라도 K8s Secret 을 그대로 재사용할 수 있도록 정렬했다.
	// 로컬 개발 호환을 위해 DATABASE_URL 이 설정된 경우에만 그 값을 우선 사용한다.
	dsn := buildDSN()

	var err error
	db, err = pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// DB 연결이 실제로 가능한지 확인합니다.
	if err := db.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	// OpenAI embedding API 호출용 클라이언트를 초기화합니다.
	embeddingClient = NewEmbeddingClient()

	// Gin 기본 라우터를 생성합니다. Logger/Recovery middleware가 포함됩니다.
	r := gin.Default()

	// K8s liveness/readiness probe 용 헬스 엔드포인트.
	// /healthz 는 프로세스 살아있음만 확인하고, /readyz 는 DB 연결까지 확인한다.
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/readyz", func(c *gin.Context) {
		if err := db.Ping(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "db_unreachable", "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// 모든 API는 /api/v1 prefix 아래에 등록합니다.
	api := r.Group("/api/v1")
	{
		// 자산 관리 API
		api.POST("/assets", createAsset)
		api.GET("/assets", listAssets)
		api.GET("/assets/:asset_id", getAsset)

		// 취약점/CVE 관리 API
		api.POST("/vulnerabilities", createVulnerabilities)
		api.GET("/assets/:asset_id/vulnerabilities", listAssetVulnerabilities)

		// 외부 노출도 관리 API
		api.POST("/exposures", createExposure)
		api.GET("/exposures", listExposures)

		// ISMS-P 통제항목 관리 API
		api.POST("/isms-p/controls", createISMSControl)
		api.GET("/isms-p/controls", listISMSControls)
		api.GET("/isms-p/controls/:control_id", getISMSControl)

		// Evidence 생성/조회 API
		api.POST("/evidence/generate", generateEvidence)
		api.GET("/evidence", listEvidence)

		// pgvector 기반 유사도 검색 API
		api.POST("/vector-search/isms-p", vectorSearchISMSP)

		// ISMS-P 매핑 실행/조회 API
		api.POST("/isms-p/mappings/run", runMapping)
		api.GET("/isms-p/mappings", listMappings)
		api.GET("/isms-p/mappings/:mapping_id", getMapping)
	}

	log.Println("server started at :8080")
	addr := ":" + envOr("SERVER_PORT", "8080")
	log.Printf("server started at %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

// buildDSN 은 vara-backend 의 config.PostgresConfig.DSN() 과 동일한 libpq KV 형식 문자열을
// 환경변수로부터 조립한다. POSTGRES_* 6개를 사용하며, 로컬 호환을 위해 DATABASE_URL 이 명시된
// 경우에는 해당 URL 을 그대로 사용한다.
func buildDSN() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOr("POSTGRES_HOST", "localhost"),
		envOr("POSTGRES_PORT", "5432"),
		envOr("POSTGRES_USER", "vara"),
		os.Getenv("POSTGRES_PASSWORD"),
		envOr("POSTGRES_DB", "vara"),
		envOr("POSTGRES_SSLMODE", "disable"),
	)
}

// envOr 은 환경변수 값이 비어 있으면 기본값을 반환한다.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// success는 모든 API 성공 응답 형식을 통일하기 위한 helper 함수입니다.
func success(c *gin.Context, data any, message string) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    data,
		"message": message,
	})
}

// fail은 모든 API 실패 응답 형식을 통일하기 위한 helper 함수입니다.
func fail(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"success": false,
		"error": gin.H{
			"message": message,
		},
	})
}

// createAsset은 자산 정보를 등록하거나 기존 asset_id가 있으면 업데이트합니다.
func createAsset(c *gin.Context) {
	var req AssetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	// 최소 필수값이 없으면 잘못된 요청으로 처리합니다.
	if req.AssetID == "" || req.AssetType == "" || req.Name == "" {
		fail(c, http.StatusBadRequest, "asset_id, asset_type, name are required")
		return
	}

	// asset_id는 UNIQUE이므로 이미 존재하면 최신 정보로 갱신합니다.
	_, err := db.Exec(
		c.Request.Context(),
		`
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
		req.AssetID,
		req.AssetType,
		req.Name,
		req.Namespace,
		req.Cluster,
		req.CloudProvider,
		req.Image,
		req.ServiceAccount,
		req.Metadata,
	)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	success(c, gin.H{
		"asset_id": req.AssetID,
		"status":   "CREATED",
	}, "asset created")
}

// listAssets는 최근 등록된 자산 목록을 최대 100개까지 조회합니다.
func listAssets(c *gin.Context) {
	rows, err := db.Query(
		c.Request.Context(),
		`
		SELECT asset_id, asset_type, name, namespace, cluster_name, cloud_provider, image, service_account
		FROM compliance_assets
		ORDER BY id DESC
		LIMIT 100
		`,
	)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}

	for rows.Next() {
		var assetID, assetType, name string
		var namespace, cluster, provider, image, serviceAccount *string

		err := rows.Scan(&assetID, &assetType, &name, &namespace, &cluster, &provider, &image, &serviceAccount)
		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		items = append(items, gin.H{
			"asset_id":        assetID,
			"asset_type":      assetType,
			"name":            name,
			"namespace":       namespace,
			"cluster":         cluster,
			"cloud_provider":  provider,
			"image":           image,
			"service_account": serviceAccount,
		})
	}

	success(c, gin.H{"items": items}, "success")
}

// getAsset은 asset_id 기준으로 특정 자산 상세 정보를 조회합니다.
func getAsset(c *gin.Context) {
	assetID := c.Param("asset_id")

	var assetType, name string
	var namespace, cluster, provider, image, serviceAccount *string

	err := db.QueryRow(
		c.Request.Context(),
		`
		SELECT asset_type, name, namespace, cluster_name, cloud_provider, image, service_account
		FROM compliance_assets
		WHERE asset_id = $1
		`,
		assetID,
	).Scan(&assetType, &name, &namespace, &cluster, &provider, &image, &serviceAccount)

	if err != nil {
		fail(c, http.StatusNotFound, "asset not found")
		return
	}

	success(c, gin.H{
		"asset_id":        assetID,
		"asset_type":      assetType,
		"name":            name,
		"namespace":       namespace,
		"cluster":         cluster,
		"cloud_provider":  provider,
		"image":           image,
		"service_account": serviceAccount,
	}, "success")
}

// createVulnerabilities는 특정 자산에 대해 Trivy 등에서 나온 CVE 목록을 저장합니다.
func createVulnerabilities(c *gin.Context) {
	var req VulnerabilityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	count := 0

	for _, v := range req.Vulnerabilities {
		_, err := db.Exec(
			c.Request.Context(),
			`
			INSERT INTO compliance_vulnerabilities (
				asset_id, image, scanner, cve_id, package_name,
				installed_version, fixed_version, severity, cvss, epss,
				kev, description, patch_status
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			`,
			req.AssetID,
			req.Image,
			req.Scanner,
			v.CVEID,
			v.PackageName,
			v.InstalledVersion,
			v.FixedVersion,
			v.Severity,
			v.CVSS,
			v.EPSS,
			v.KEV,
			v.Description,
			v.PatchStatus,
		)

		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		count++
	}

	success(c, gin.H{
		"asset_id":       req.AssetID,
		"inserted_count": count,
	}, "vulnerabilities saved")
}

// listAssetVulnerabilities는 특정 자산에 연결된 취약점 목록을 CVSS 높은 순으로 조회합니다.
func listAssetVulnerabilities(c *gin.Context) {
	assetID := c.Param("asset_id")

	rows, err := db.Query(
		c.Request.Context(),
		`
		SELECT cve_id, package_name, severity, cvss, epss, kev, patch_status, description
		FROM compliance_vulnerabilities
		WHERE asset_id = $1
		ORDER BY cvss DESC NULLS LAST
		`,
		assetID,
	)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}

	for rows.Next() {
		var cveID, packageName, severity, patchStatus, description *string
		var cvss, epss *float64
		var kev *bool

		if err := rows.Scan(&cveID, &packageName, &severity, &cvss, &epss, &kev, &patchStatus, &description); err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		items = append(items, gin.H{
			"cve_id":       cveID,
			"package_name": packageName,
			"severity":     severity,
			"cvss":         cvss,
			"epss":         epss,
			"kev":          kev,
			"patch_status": patchStatus,
			"description":  description,
		})
	}

	success(c, gin.H{
		"asset_id":        assetID,
		"vulnerabilities": items,
	}, "success")
}

// createExposure는 자산의 외부 노출 정보를 저장합니다.
func createExposure(c *gin.Context) {
	var req ExposureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	_, err := db.Exec(
		c.Request.Context(),
		`
		INSERT INTO compliance_exposures (
			asset_id, exposure_level, exposure_type, entrypoint,
			protocol, port, auth_required, description, metadata
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		`,
		req.AssetID,
		req.ExposureLevel,
		req.ExposureType,
		req.Entrypoint,
		req.Protocol,
		req.Port,
		req.AuthRequired,
		req.Description,
		req.Metadata,
	)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	success(c, gin.H{
		"asset_id":        req.AssetID,
		"exposure_level":  req.ExposureLevel,
		"exposure_type":   req.ExposureType,
		"exposure_status": "CREATED",
	}, "exposure saved")
}

// listExposures는 노출 정보를 조회합니다. level 쿼리가 있으면 E3/E4 등 특정 등급만 필터링합니다.
func listExposures(c *gin.Context) {
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

	rows, err := db.Query(c.Request.Context(), query, args...)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
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
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		items = append(items, gin.H{
			"asset_id":       assetID,
			"exposure_level": exposureLevel,
			"exposure_type":  exposureType,
			"entrypoint":     entrypoint,
			"protocol":       protocol,
			"port":           port,
			"auth_required":  authRequired,
			"description":    description,
		})
	}

	success(c, gin.H{"items": items}, "success")
}

// createISMSControl은 ISMS-P 통제항목을 저장하고, 검색용 embedding vector도 함께 생성합니다.
func createISMSControl(c *gin.Context) {
	var req ISMSControlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	// ISMS-P 항목의 제목/설명/키워드를 하나의 검색용 문장으로 합칩니다.
	text := buildISMSControlEmbeddingText(req)

	// 통제항목 문장을 실제 embedding vector로 변환합니다.
	embedding, err := embeddingClient.CreateEmbedding(text)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	// pgvector 컬럼에 넣을 수 있도록 [0.1,0.2,...] 문자열로 변환합니다.
	vector := toPgVector(embedding)

	_, err = db.Exec(
		c.Request.Context(),
		`
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
		req.ControlID,
		req.Domain,
		req.Title,
		req.Description,
		req.Keywords,
		vector,
	)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	success(c, gin.H{
		"control_id":       req.ControlID,
		"embedding_status": "CREATED",
	}, "isms-p control created")
}

// listISMSControls는 등록된 ISMS-P 통제항목 목록을 조회합니다.
func listISMSControls(c *gin.Context) {
	rows, err := db.Query(
		c.Request.Context(),
		`
		SELECT control_id, domain, title, description, keywords
		FROM compliance_isms_p_controls
		ORDER BY control_id
		LIMIT 100
		`,
	)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}

	for rows.Next() {
		var controlID, title string
		var domain, description *string
		var keywords []string

		if err := rows.Scan(&controlID, &domain, &title, &description, &keywords); err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		items = append(items, gin.H{
			"control_id":  controlID,
			"domain":      domain,
			"title":       title,
			"description": description,
			"keywords":    keywords,
		})
	}

	success(c, gin.H{"items": items}, "success")
}

// getISMSControl은 control_id 기준으로 특정 ISMS-P 통제항목을 조회합니다.
func getISMSControl(c *gin.Context) {
	controlID := c.Param("control_id")

	var domain, description *string
	var title string
	var keywords []string

	err := db.QueryRow(
		c.Request.Context(),
		`
		SELECT domain, title, description, keywords
		FROM compliance_isms_p_controls
		WHERE control_id = $1
		`,
		controlID,
	).Scan(&domain, &title, &description, &keywords)

	if err != nil {
		fail(c, http.StatusNotFound, "control not found")
		return
	}

	success(c, gin.H{
		"control_id":  controlID,
		"domain":      domain,
		"title":       title,
		"description": description,
		"keywords":    keywords,
	}, "success")
}

// generateEvidence는 CVE/EXPOSURE 같은 구조화 데이터를 RAG 검색용 문장형 Evidence로 생성합니다.
func generateEvidence(c *gin.Context) {
	var req EvidenceGenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	// 요청된 source_types를 빠르게 확인하기 위해 set 형태로 변환합니다.
	sourceSet := map[string]bool{}
	for _, s := range req.SourceTypes {
		sourceSet[strings.ToUpper(s)] = true
	}

	evidenceIDs := []int{}

	if len(sourceSet) == 0 || sourceSet["CVE"] {
		ids, err := generateCVEEvidence(c.Request.Context(), req.AssetID)
		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
		evidenceIDs = append(evidenceIDs, ids...)
	}

	if len(sourceSet) == 0 || sourceSet["EXPOSURE"] {
		ids, err := generateExposureEvidence(c.Request.Context(), req.AssetID)
		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
		evidenceIDs = append(evidenceIDs, ids...)
	}

	if len(sourceSet) == 0 || sourceSet["ASSET"] {
		ids, err := generateAssetEvidence(c.Request.Context(), req.AssetID)
		if err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}
		evidenceIDs = append(evidenceIDs, ids...)
	}

	success(c, gin.H{
		"asset_id":        req.AssetID,
		"generated_count": len(evidenceIDs),
		"evidence_ids":    evidenceIDs,
	}, "evidence generated")
}

// generateCVEEvidence는 vulnerabilities 테이블의 CVE 정보를 문장형 evidence로 변환하고 embedding을 저장합니다.
func generateCVEEvidence(ctx context.Context, assetID string) ([]int, error) {
	rows, err := db.Query(
		ctx,
		`
		SELECT cve_id, severity, cvss, epss, kev, description, patch_status
		FROM compliance_vulnerabilities
		WHERE asset_id = $1
		`,
		assetID,
	)
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

		// CVE 구조화 데이터를 RAG가 이해하기 쉬운 자연어 Evidence 문장으로 변환합니다.
		text := fmt.Sprintf(
			"자산 %s에서 %s 취약점이 발견되었다. 심각도는 %s이고 CVSS는 %.1f, EPSS는 %.2f이다. KEV 포함 여부는 %t이다. 패치 상태는 %s이다. 설명: %s",
			assetID,
			valueString(cveID),
			valueString(severity),
			valueFloat(cvss),
			valueFloat(epss),
			valueBool(kev),
			valueString(patchStatus),
			valueString(description),
		)

		// Evidence 문장을 embedding vector로 변환합니다.
		embedding, err := embeddingClient.CreateEmbedding(text)
		if err != nil {
			return nil, err
		}

		vector := toPgVector(embedding)

		var id int
		err = db.QueryRow(
			ctx,
			`
			INSERT INTO compliance_evidence_documents (
				source_type, asset_id, cve_id, severity, document_text, embedding
			)
			VALUES ('CVE', $1, $2, $3, $4, $5::vector)
			RETURNING id
			`,
			assetID,
			valueString(cveID),
			valueString(severity),
			text,
			vector,
		).Scan(&id)

		if err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	return ids, nil
}

// generateExposureEvidence는 exposures 테이블의 노출 정보를 문장형 evidence로 변환하고 embedding을 저장합니다.
func generateExposureEvidence(ctx context.Context, assetID string) ([]int, error) {
	rows, err := db.Query(
		ctx,
		`
		SELECT exposure_level, exposure_type, entrypoint, protocol, port, auth_required, description
		FROM compliance_exposures
		WHERE asset_id = $1
		`,
		assetID,
	)
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

		// 노출도 구조화 데이터를 RAG가 이해하기 쉬운 자연어 Evidence 문장으로 변환합니다.
		text := fmt.Sprintf(
			"자산 %s는 노출 등급 %s에 해당한다. 노출 유형은 %s이고 진입점은 %s, 프로토콜은 %s, 포트는 %d이다. 인증 필요 여부는 %t이다. 설명: %s",
			assetID,
			exposureLevel,
			valueString(exposureType),
			valueString(entrypoint),
			valueString(protocol),
			valueInt(port),
			valueBool(authRequired),
			valueString(description),
		)

		embedding, err := embeddingClient.CreateEmbedding(text)
		if err != nil {
			return nil, err
		}

		vector := toPgVector(embedding)

		var id int
		err = db.QueryRow(
			ctx,
			`
			INSERT INTO compliance_evidence_documents (
				source_type, asset_id, exposure_level, document_text, embedding
			)
			VALUES ('EXPOSURE', $1, $2, $3, $4::vector)
			RETURNING id
			`,
			assetID,
			exposureLevel,
			text,
			vector,
		).Scan(&id)

		if err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	return ids, nil
}

// generateAssetEvidence는 assets 테이블의 자산 자체 속성(이미지, ServiceAccount, privileged,
// hostNetwork, RDS 암호화 여부 등)을 ISMS-P 매핑에 활용 가능한 자연어 Evidence 문장으로 변환한다.
// asset_type 별로 별도 템플릿을 사용하며(pod / rds / generic), 검색에 도움이 되는 보안 우려 사항만
// 추가 문장으로 풀어 써서 BGE-M3 임베딩이 ISMS-P 통제 키워드(특수 권한, 네트워크 분리, 패치관리 등)와
// 의미적으로 가까워지도록 한다.
func generateAssetEvidence(ctx context.Context, assetID string) ([]int, error) {
	// assetID 가 비어 있으면 전체 자산을 대상으로 한다 (전체 evidence rebuild 시나리오).
	rows, err := db.Query(
		ctx,
		`
		SELECT asset_id, asset_type, name, namespace, cluster_name,
		       cloud_provider, image, service_account, metadata
		FROM compliance_assets
		WHERE ($1 = '' OR asset_id = $1)
		`,
		assetID,
	)
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

		// JSONB 컬럼은 []byte 로 받아 안전하게 unmarshal 한다 (NULL/빈 객체 대응).
		var metadata map[string]any
		if len(metadataBytes) > 0 {
			_ = json.Unmarshal(metadataBytes, &metadata)
		}

		text := buildAssetEvidenceText(
			aid, atype, name,
			valueString(namespace),
			valueString(cluster),
			valueString(provider),
			valueString(image),
			valueString(sa),
			metadata,
		)

		embedding, err := embeddingClient.CreateEmbedding(text)
		if err != nil {
			return nil, err
		}

		vector := toPgVector(embedding)

		var id int
		err = db.QueryRow(
			ctx,
			`
			INSERT INTO compliance_evidence_documents (
				source_type, asset_id, namespace, document_text, metadata, embedding
			)
			VALUES ('ASSET', $1, $2, $3, $4, $5::vector)
			RETURNING id
			`,
			aid,
			valueString(namespace),
			text,
			metadata,
			vector,
		).Scan(&id)

		if err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	return ids, nil
}

// buildAssetEvidenceText는 asset_type 별로 적절한 자연어 문장 템플릿을 분기한다.
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

// buildPodEvidenceText는 Pod 자산의 보안 컨텍스트(privileged / hostNetwork / SA / 이미지 태그)를
// ISMS-P 통제 매칭이 잘 되도록 풀어쓴 문장을 생성한다.
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
		assetID,
		valueOrDash(cloudProvider),
		valueOrDash(cluster),
		valueOrDash(namespace),
		name,
		valueOrDash(image),
		valueOrDash(serviceAccount),
		privileged, hostNetwork,
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

// buildRDSEvidenceText는 RDS 인스턴스의 PubliclyAccessible / 암호화 / IAM 인증 / 백업 / MultiAZ
// 같은 속성을 ISMS-P 데이터베이스 접근·암호화·재해복구 항목과 매칭되도록 자연어로 풀어쓴다.
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
		assetID,
		valueOrDash(cluster),
		name,
		valueOrDash(engine), valueOrDash(version), valueOrDash(class),
		pubAccess, encrypted, iamAuth, multiAZ, delProt, backupDays,
	)

	concerns := []string{}
	if pubAccess {
		concerns = append(concerns,
			"PubliclyAccessible=true 로 인터넷 경로에서 데이터베이스 endpoint 에 도달 가능하다.")
	}
	if !encrypted {
		concerns = append(concerns,
			"StorageEncrypted=false 로 저장 데이터가 KMS 기반으로 암호화되지 않아 암호정책 적용이 미흡하다.")
	}
	if !iamAuth {
		concerns = append(concerns,
			"IAMDatabaseAuthenticationEnabled=false 로 IAM 기반 DB 인증이 적용되지 않아 비밀번호 기반 인증에만 의존한다.")
	}
	if !multiAZ {
		concerns = append(concerns,
			"MultiAZ=false 로 단일 가용영역에서 운영되어 가용성 및 재해복구 요건 충족이 어렵다.")
	}
	if !delProt {
		concerns = append(concerns,
			"DeletionProtection=false 로 인스턴스 삭제 보호가 활성화되어 있지 않다.")
	}
	if backupDays == 0 {
		concerns = append(concerns,
			"BackupRetentionPeriod=0 으로 자동 백업이 비활성화되어 백업 및 복구관리가 미흡하다.")
	}

	if len(concerns) > 0 {
		base += " 보안 및 가용성 우려: " + strings.Join(concerns, " ")
	}
	return base
}

// buildGenericAssetEvidenceText는 pod/rds 외의 자산 유형을 위한 기본 템플릿이다.
func buildGenericAssetEvidenceText(
	assetID, assetType, name, namespace, cluster, cloudProvider, image, serviceAccount string,
) string {
	return fmt.Sprintf(
		"자산 %s 는 cloud_provider=%s 클러스터 %s 의 %s 자산 %s 이다. "+
			"namespace=%s, image=%s, service_account=%s.",
		assetID,
		valueOrDash(cloudProvider),
		valueOrDash(cluster),
		assetType,
		name,
		valueOrDash(namespace),
		valueOrDash(image),
		valueOrDash(serviceAccount),
	)
}

// metaString 은 JSONB 메타데이터에서 문자열 값을 안전하게 추출한다.
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

// metaBool 은 JSONB 메타데이터에서 bool 값을 안전하게 추출한다.
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

// metaInt 는 JSONB 메타데이터에서 정수 값을 안전하게 추출한다.
// JSON 디코딩 시 숫자는 float64 로 들어오므로 다중 타입 변환을 처리한다.
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

// valueOrDash 는 빈 문자열을 "-" 로 치환해 자연어 문장의 가독성을 보장한다.
func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// isUnpinnedTag 는 컨테이너 이미지 태그가 누락되었거나 latest 로 고정되어 있는지를 판별한다.
// 패치관리 통제 항목과의 매칭을 강조하기 위한 단순 휴리스틱이다.
func isUnpinnedTag(image string) bool {
	if image == "" {
		return true
	}
	if strings.Contains(image, ":latest") {
		return true
	}
	// host:port/path 형식을 고려해 마지막 path segment 에서만 ':' 존재 여부를 본다.
	lastSlash := strings.LastIndex(image, "/")
	last := image[lastSlash+1:]
	return !strings.Contains(last, ":")
}

// listEvidence는 생성된 Evidence 문서 목록을 조회합니다.
func listEvidence(c *gin.Context) {
	rows, err := db.Query(
		c.Request.Context(),
		`
		SELECT id, source_type, asset_id, cve_id, severity, exposure_level, document_text
		FROM compliance_evidence_documents
		ORDER BY id DESC
		LIMIT 100
		`,
	)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	items := []gin.H{}

	for rows.Next() {
		var id int
		var sourceType, documentText string
		var assetID, cveID, severity, exposureLevel *string

		if err := rows.Scan(&id, &sourceType, &assetID, &cveID, &severity, &exposureLevel, &documentText); err != nil {
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		items = append(items, gin.H{
			"evidence_id":    id,
			"source_type":    sourceType,
			"asset_id":       assetID,
			"cve_id":         cveID,
			"severity":       severity,
			"exposure_level": exposureLevel,
			"document_text":  documentText,
		})
	}

	success(c, gin.H{"items": items}, "success")
}

// vectorSearchISMSP는 ISMS-P 통제항목 텍스트를 query로 사용해 관련 Evidence를 pgvector로 검색합니다.
func vectorSearchISMSP(c *gin.Context) {
	var req VectorSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	if req.TopK <= 0 {
		req.TopK = 10
	}
	if req.MinSimilarity <= 0 {
		req.MinSimilarity = 0.5
	}

	controlText, err := getControlSearchText(c.Request.Context(), req.ControlID)
	if err != nil {
		fail(c, http.StatusNotFound, "control not found")
		return
	}

	results, err := searchEvidenceByText(c.Request.Context(), controlText, req.TopK, req.MinSimilarity, req.SourceTypes)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	success(c, gin.H{
		"control_id": req.ControlID,
		"query_text": controlText,
		"results":    results,
	}, "vector search completed")
}

// runMapping은 ISMS-P 항목 기준으로 Evidence 검색을 수행한 뒤 rule 기반으로 준수 상태를 판단하고 결과를 저장합니다.
func runMapping(c *gin.Context) {
	var req MappingRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return
	}

	if req.TopK <= 0 {
		req.TopK = 10
	}
	if req.MinSimilarity <= 0 {
		req.MinSimilarity = 0.5
	}

	controlText, err := getControlSearchText(c.Request.Context(), req.ControlID)
	if err != nil {
		fail(c, http.StatusNotFound, "control not found")
		return
	}

	results, err := searchEvidenceByText(c.Request.Context(), controlText, req.TopK, req.MinSimilarity, req.SourceTypes)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	status, riskLevel, riskScore, summary, reason, recommendations := judgeMapping(results)

	evidenceIDs := []int{}
	for _, r := range results {
		evidenceIDs = append(evidenceIDs, r.EvidenceID)
	}

	var mappingID int
	err = db.QueryRow(
		c.Request.Context(),
		`
		INSERT INTO compliance_isms_p_mappings (
			control_id, status, risk_level, risk_score, summary, reason, recommendations, evidence_ids
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id
		`,
		req.ControlID,
		status,
		riskLevel,
		riskScore,
		summary,
		reason,
		recommendations,
		evidenceIDs,
	).Scan(&mappingID)

	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
		return
	}

	success(c, gin.H{
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

// listMappings는 최근 ISMS-P 매핑 결과 목록을 조회합니다.
func listMappings(c *gin.Context) {
	rows, err := db.Query(
		c.Request.Context(),
		`
		SELECT id, control_id, status, risk_level, risk_score, summary, created_at
		FROM compliance_isms_p_mappings
		ORDER BY id DESC
		LIMIT 100
		`,
	)
	if err != nil {
		fail(c, http.StatusInternalServerError, err.Error())
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
			fail(c, http.StatusInternalServerError, err.Error())
			return
		}

		items = append(items, gin.H{
			"mapping_id": id,
			"control_id": controlID,
			"status":     status,
			"risk_level": riskLevel,
			"risk_score": riskScore,
			"summary":    summary,
			"created_at": createdAt,
		})
	}

	success(c, gin.H{"items": items}, "success")
}

// getMapping은 mapping_id 기준으로 특정 매핑 결과 상세 정보를 조회합니다.
func getMapping(c *gin.Context) {
	mappingID := c.Param("mapping_id")

	var id int
	var controlID, status, riskLevel, summary, reason string
	var riskScore float64
	var recommendations []string
	var evidenceIDs []int
	var createdAt time.Time

	err := db.QueryRow(
		c.Request.Context(),
		`
		SELECT id, control_id, status, risk_level, risk_score, summary, reason, recommendations, evidence_ids, created_at
		FROM compliance_isms_p_mappings
		WHERE id = $1
		`,
		mappingID,
	).Scan(&id, &controlID, &status, &riskLevel, &riskScore, &summary, &reason, &recommendations, &evidenceIDs, &createdAt)

	if err != nil {
		fail(c, http.StatusNotFound, "mapping not found")
		return
	}

	success(c, gin.H{
		"mapping_id":      id,
		"control_id":      controlID,
		"status":          status,
		"risk_level":      riskLevel,
		"risk_score":      riskScore,
		"summary":         summary,
		"reason":          reason,
		"recommendations": recommendations,
		"evidence_ids":    evidenceIDs,
		"created_at":      createdAt,
	}, "success")
}

// getControlSearchText는 ISMS-P 항목의 domain/title/description/keywords를 합쳐 검색용 문장으로 만듭니다.
func getControlSearchText(ctx context.Context, controlID string) (string, error) {
	var domain, description *string
	var title string
	var keywords []string

	err := db.QueryRow(
		ctx,
		`
		SELECT domain, title, description, keywords
		FROM compliance_isms_p_controls
		WHERE control_id = $1
		`,
		controlID,
	).Scan(&domain, &title, &description, &keywords)

	if err != nil {
		return "", err
	}

	text := fmt.Sprintf(
		"ISMS-P 항목 %s. 분류: %s. 제목: %s. 설명: %s. 관련 키워드: %s.",
		controlID,
		valueString(domain),
		title,
		valueString(description),
		strings.Join(keywords, ", "),
	)

	return text, nil
}

// searchEvidenceByText는 query 문장을 embedding으로 변환한 뒤 evidence_documents.embedding과 cosine 유사도 검색을 수행합니다.
func searchEvidenceByText(
	ctx context.Context,
	queryText string,
	topK int,
	minSimilarity float64,
	sourceTypes []string,
) ([]SearchResult, error) {
	// 검색 질의도 Evidence와 같은 embedding 공간으로 변환해야 cosine 유사도 비교가 가능합니다.
	queryEmbedding, err := embeddingClient.CreateEmbedding(queryText)
	if err != nil {
		return nil, err
	}

	vector := toPgVector(queryEmbedding)

	rows, err := db.Query(
		ctx,
		`
		SELECT
			id,
			source_type,
			asset_id,
			cve_id,
			severity,
			exposure_level,
			document_text,
			1 - (embedding <=> $1::vector) AS similarity
		FROM compliance_evidence_documents
		ORDER BY embedding <=> $1::vector
		LIMIT $2
		`,
		vector,
		topK,
	)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// source_types가 지정되면 CVE, EXPOSURE 등 원하는 Evidence 종류만 남깁니다.
	sourceFilter := map[string]bool{}
	for _, s := range sourceTypes {
		sourceFilter[strings.ToUpper(s)] = true
	}

	results := []SearchResult{}

	for rows.Next() {
		var r SearchResult
		var assetID, cveID, severity, exposureLevel *string

		err := rows.Scan(
			&r.EvidenceID,
			&r.SourceType,
			&assetID,
			&cveID,
			&severity,
			&exposureLevel,
			&r.DocumentText,
			&r.Similarity,
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

// judgeMapping은 검색된 Evidence를 바탕으로 간단한 rule 기반 위험도와 준수 상태를 산정합니다.
// 현재는 LLM 판단이 아니라 MVP용 룰 엔진입니다.
func judgeMapping(results []SearchResult) (
	status string,
	riskLevel string,
	riskScore float64,
	summary string,
	reason string,
	recommendations []string,
) {
	if len(results) == 0 {
		return "UNKNOWN",
			"LOW",
			0.0,
			"관련 evidence가 부족하여 판단할 수 없다.",
			"ISMS-P 항목과 직접 연결되는 자산, 취약점, 노출 근거가 검색되지 않았다.",
			[]string{"관련 자산, 취약점, 노출도 evidence를 추가 수집한다."}
	}

	// 유사도와 Evidence 종류를 기반으로 간단한 위험도 산정에 필요한 flag를 계산합니다.
	maxSim := 0.0
	hasCritical := false
	hasHigh := false
	hasExposure := false
	hasE4 := false
	hasCVE := false

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

	// MVP용 점수식: 유사도 + CVE 심각도 + 노출 여부를 가중합으로 계산합니다.
	score := 0.0
	score += maxSim * 0.45

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

	if hasCVE && hasExposure && score >= 0.70 {
		status = "NON_COMPLIANT"
		summary = "취약점 evidence와 외부 노출 evidence가 함께 확인되어 미준수 가능성이 높다."
		reason = "검색된 evidence에서 취약점과 외부 노출 근거가 동시에 발견되었다. 운영 자산이 외부에 노출되어 있고 고위험 취약점이 존재하는 경우 ISMS-P 취약점 관리 및 보안관리 항목에서 미흡으로 판단할 수 있다."
		recommendations = []string{
			"취약 패키지를 fixed version으로 업데이트한다.",
			"패치 전까지 public ingress 또는 외부 접근 경로를 제한한다.",
			"조치 완료 후 재스캔 결과를 evidence로 저장한다.",
		}
	} else if score >= 0.45 {
		status = "NEEDS_REVIEW"
		summary = "관련 evidence는 존재하지만 미준수로 단정하기에는 추가 확인이 필요하다."
		reason = "검색된 evidence의 유사도는 의미가 있으나, 취약점 조치 여부, 외부 노출 여부, 운영 영향도 중 일부 근거가 부족하다."
		recommendations = []string{
			"패치 상태, 외부 노출 상태, 접근 권한 정보를 추가 확인한다.",
			"관련 evidence를 보완한 뒤 매핑을 재실행한다.",
		}
	} else {
		status = "COMPLIANT"
		summary = "현재 evidence 기준으로 명확한 미준수 근거는 확인되지 않았다."
		reason = "검색된 evidence의 위험도가 낮거나 ISMS-P 항목과의 직접 관련성이 낮다."
		recommendations = []string{
			"정기적으로 취약점 스캔과 evidence 갱신을 수행한다.",
		}
	}

	return status, riskLevel, round(score), summary, reason, recommendations
}

// buildISMSControlEmbeddingText는 ISMS-P 항목을 embedding하기 좋은 설명형 텍스트로 변환합니다.
func buildISMSControlEmbeddingText(req ISMSControlRequest) string {
	return fmt.Sprintf(
		"ISMS-P 항목 %s. 분류: %s. 제목: %s. 설명: %s. 관련 키워드: %s.",
		req.ControlID,
		req.Domain,
		req.Title,
		req.Description,
		strings.Join(req.Keywords, ", "),
	)
}

// EmbeddingClient는 OpenAI Embedding API 호출에 필요한 설정과 HTTP 클라이언트를 보관합니다.
type EmbeddingClient struct {
	Model  string
	URL    string
	Client *http.Client
}

// OpenAIEmbeddingRequest는 OpenAI /v1/embeddings 요청 payload 구조입니다.
type LocalEmbeddingRequest struct {
	Text string `json:"text"`
}

// OpenAIEmbeddingResponse는 OpenAI embedding 응답 중 필요한 필드만 파싱하기 위한 구조입니다.
type LocalEmbeddingResponse struct {
	Model     string    `json:"model"`
	Dimension int       `json:"dimension"`
	Embedding []float64 `json:"embedding"`
}

// NewEmbeddingClient는 BGE-M3 임베딩 서버 클라이언트를 생성합니다.
// K8s 환경에서는 EMBEDDING_SERVER_URL env 로 Service DNS 를 주입하고,
// 로컬에서는 기본값(localhost:9000) 으로 동작합니다.
func NewEmbeddingClient() *EmbeddingClient {
	return &EmbeddingClient{
		Model: "BAAI/bge-m3",
		URL:   envOr("EMBEDDING_SERVER_URL", "http://localhost:9000/embed"),
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// CreateEmbedding은 입력 텍스트를 OpenAI embedding vector로 변환합니다.
func (c *EmbeddingClient) CreateEmbedding(text string) ([]float64, error) {
	reqBody := LocalEmbeddingRequest{
		Text: text,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	log.Println("========== BGE-M3 EMBEDDING INPUT ==========")
	log.Printf("url: %s\n", c.URL)
	log.Printf("input text: %s\n", text)
	log.Printf("request json: %s\n", string(bodyBytes))
	log.Println("============================================")

	req, err := http.NewRequest(
		http.MethodPost,
		c.URL,
		bytes.NewBuffer(bodyBytes),
	)
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
	// ===== BGE-M3 출력 로그 =====
	previewSize := 8
	if len(result.Embedding) < previewSize {
		previewSize = len(result.Embedding)
	}

	log.Println("========== BGE-M3 EMBEDDING OUTPUT =========")
	log.Printf("response model: %s\n", result.Model)
	log.Printf("response dimension: %d\n", result.Dimension)
	log.Printf("embedding length: %d\n", len(result.Embedding))
	log.Printf("embedding preview: %v\n", result.Embedding[:previewSize])
	log.Println("============================================")

	return result.Embedding, nil
}

// toPgVector는 Go의 []float64 벡터를 PostgreSQL pgvector가 받을 수 있는 문자열 형식으로 변환합니다.
func toPgVector(vec []float64) string {
	parts := make([]string, len(vec))
	for i, v := range vec {
		parts[i] = fmt.Sprintf("%.8f", v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// valueString은 nullable string 포인터를 안전하게 빈 문자열로 변환합니다.
func valueString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// valueFloat은 nullable float 포인터를 안전하게 0으로 변환합니다.
func valueFloat(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

// valueBool은 nullable bool 포인터를 안전하게 false로 변환합니다.
func valueBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// valueInt는 nullable int 포인터를 안전하게 0으로 변환합니다.
func valueInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// round는 risk score를 소수점 둘째 자리까지 반올림합니다.
func round(v float64) float64 {
	return math.Round(v*100) / 100
}
