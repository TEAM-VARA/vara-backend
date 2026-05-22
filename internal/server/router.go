package server

import (
	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/handler"
)

func newRouter(
	health *handler.HealthHandler,
	agent *handler.AgentHandler,
	scoring *handler.ScoringHandler,
	clusterReader *handler.ClusterReaderHandler,
	grc *handler.GRCHandler,
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

		// ── 단순 Pod 이벤트 (scan-pod.sh 같은 도구용) ──
		api.POST("/agents/cluster-reader/pod-events", agent.PodEvents)

		// ── eBPF Agent ──
		api.POST("/agents/ebpf/traffic", agent.Traffic)

		// ── SBOM ──
		api.POST("/agents/sbom", agent.SBOM)

		// ── Risk Scoring ──
		api.POST("/pods/:pod_id/risk", scoring.ComputeRisk)
		api.GET("/pods/:pod_id/risk/details", scoring.GetRiskDetails)

		// ── GRC Compliance Check (v2) ──
		api.POST("/compliance/checks", grc.CreateCheck)
		api.GET("/compliance/checks", grc.ListChecks)
		api.GET("/compliance/checks/:check_id", grc.GetCheck)
		api.GET("/compliance/checks/:check_id/evidence", grc.ListEvidence)
		api.GET("/rulesets", grc.ListRulesets)
		api.GET("/rulesets/:item_id", grc.GetRuleset)

		// ── Cloud Environments ──
		api.POST("/compliance/cloud-environments", grc.CreateCloudEnvironments)
		api.GET("/compliance/cloud-environments", grc.ListCloudEnvironments)

		// ── Backward-compat aliases (deprecated) ──
		api.POST("/compliance/check", grc.CreateCheck)
		api.GET("/compliance/check/:check_id", grc.GetCheck)
		api.GET("/compliance/scans", grc.ListChecks)
		api.GET("/compliance/scans/:check_id", grc.GetCheck)
	}

	return r
}
