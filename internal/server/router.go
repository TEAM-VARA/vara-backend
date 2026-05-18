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
	clusterReader *handler.ClusterReaderHandler,
	exposure *handler.ExposureHandler,
	globalScoring *handler.GlobalScoringHandler,
	attackPath *handler.AttackPathHandler,
) *gin.Engine {
	r := gin.Default()

	r.GET("/healthz", health.Healthz)

	api := r.Group("/api/v1")
	{
		// ── Cluster Reader Agent v2 (8개 엔드포인트) ──
		api.POST("/agents/cluster-reader/nodes", clusterReader.Nodes)
		api.POST("/agents/cluster-reader/pods", clusterReader.Pods)
		api.POST("/agents/cluster-reader/services", clusterReader.Services)
		api.POST("/agents/cluster-reader/sensitive-resources", clusterReader.Sensitive)
		api.POST("/agents/cluster-reader/ingresses", clusterReader.Ingresses)
		api.POST("/agents/cluster-reader/workloads", clusterReader.Workloads)
		api.POST("/agents/cluster-reader/network-policies", clusterReader.NetworkPolicies)
		api.POST("/agents/cluster-reader/rbac", clusterReader.RBAC)

		// ── 단순 Pod 이벤트 ──
		api.POST("/agents/cluster-reader/pod-events", agent.PodEvents)

		// ── eBPF Agent ──
		api.POST("/agents/ebpf/traffic", agent.Traffic)

		// ── SBOM ──
		api.POST("/agents/sbom", agent.SBOM)

		// ── 기존 Risk Scoring (유지) ──
		api.POST("/pods/:pod_id/risk", scoring.ComputeRisk)
		api.GET("/pods/:pod_id/risk/details", scoring.GetRiskDetails)

		// ── 인터넷 노출 (작업 C-1) ──
		api.POST("/scoring/exposure/compute", exposure.Compute)
		api.GET("/scoring/exposure/pods/:pod_uid", exposure.GetByPod)
		api.GET("/scoring/exposure/clusters/:cluster_name", exposure.GetByCluster)

		// ── Global CVE Score (작업 B-1) ──
		api.POST("/scoring/global/cves/:cve_id", globalScoring.ComputeCVE)
		api.GET("/scoring/global/cves/:cve_id", globalScoring.GetCVE)
		api.POST("/scoring/global/images", globalScoring.ComputeImage)

		// ── Attack Path Scope (작업 B-2c) ──
		api.POST("/scoring/attack-path/compute", attackPath.Compute)
		api.GET("/scoring/attack-path/pods/:pod_uid", attackPath.GetByPod)
		api.GET("/scoring/attack-path/clusters/:cluster_name", attackPath.GetByCluster)

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
