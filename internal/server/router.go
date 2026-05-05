package server

import (
	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/handler"
)

func newRouter(
	health *handler.HealthHandler,
	agent *handler.AgentHandler,
	ismsp *handler.ISMSPHandler,
	scoring *handler.ScoringHandler,
) *gin.Engine {
	r := gin.Default()

	r.GET("/healthz", health.Healthz)

	api := r.Group("/api/v1")
	{
		// ── Cluster Reader Agent ──
		api.POST("/agents/cluster-reader/pods", agent.Pods)
		api.POST("/agents/cluster-reader/services", agent.Services)
		api.POST("/agents/cluster-reader/nodes", agent.Nodes)

		// ── eBPF Agent ──
		api.POST("/agents/ebpf/traffic", agent.Traffic)

		// ── SBOM ──
		api.POST("/agents/sbom", agent.SBOM)

		// ── Risk Scoring ──
		api.POST("/pods/:pod_id/risk", scoring.ComputeRisk)
		api.GET("/pods/:pod_id/risk/details", scoring.GetRiskDetails)

		// ── ISMS-P 컴플라이언스 ──
		api.POST("/assets", ismsp.CreateAsset)
		api.GET("/assets", ismsp.ListAssets)
		api.GET("/assets/:asset_id", ismsp.GetAsset)

		api.POST("/vulnerabilities", ismsp.CreateVulnerabilities)
		api.GET("/assets/:asset_id/vulnerabilities", ismsp.ListAssetVulnerabilities)

		api.POST("/exposures", ismsp.CreateExposure)
		api.GET("/exposures", ismsp.ListExposures)

		api.POST("/isms-p/controls", ismsp.CreateISMSControl)
		api.GET("/isms-p/controls", ismsp.ListISMSControls)
		api.GET("/isms-p/controls/:control_id", ismsp.GetISMSControl)

		api.POST("/evidence/generate", ismsp.GenerateEvidence)
		api.GET("/evidence", ismsp.ListEvidence)

		api.POST("/vector-search/isms-p", ismsp.VectorSearchISMSP)

		api.POST("/isms-p/mappings/run", ismsp.RunMapping)
		api.GET("/isms-p/mappings", ismsp.ListMappings)
		api.GET("/isms-p/mappings/:mapping_id", ismsp.GetMapping)
	}

	return r
}
