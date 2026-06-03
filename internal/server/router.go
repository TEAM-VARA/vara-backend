package server

import (
	"github.com/gin-gonic/gin"

	"time"

	"github.com/gin-contrib/cors"
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
	localScoring *handler.LocalScoringHandler,
	imageGlobalCache *handler.ImageGlobalCacheHandler,
	finalScoring *handler.FinalScoringHandler,
	toxic *handler.ToxicHandler,
	sbomPackage *handler.SBOMPackageHandler,
	packageVuln *handler.PackageVulnHandler,
	ebpf *handler.EbpfHandler,
	edge *handler.EdgeHandler,
	podRefresh *handler.PodRefreshHandler,
	notif *handler.NotificationHandler,
	analysis *handler.AnalysisHandler,
	rbacChain *handler.RBACChainHandler,
	grc *handler.GRCHandler,
	breakdownH *handler.BreakdownHandler,
) *gin.Engine {
	r := gin.Default()

	// ── CORS (라우트 등록 전에!) ──
	r.Use(cors.New(cors.Config{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders: []string{"Content-Length"},
		MaxAge:        12 * time.Hour,
	}))

	r.GET("/healthz", health.Healthz)

	api := r.Group("/api/v1")
	{
		// ── Cluster Reader Agent v2 ──
		api.POST("/agents/cluster-reader/nodes", clusterReader.Nodes)
		api.POST("/agents/cluster-reader/pods", clusterReader.Pods)
		api.POST("/agents/cluster-reader/services", clusterReader.Services)
		api.POST("/agents/cluster-reader/sensitive-resources", clusterReader.Sensitive)
		api.POST("/agents/cluster-reader/ingresses", clusterReader.Ingresses)
		api.POST("/agents/cluster-reader/workloads", clusterReader.Workloads)
		api.POST("/agents/cluster-reader/network-policies", clusterReader.NetworkPolicies)
		api.POST("/agents/cluster-reader/rbac", clusterReader.RBAC)

		api.POST("/agents/cluster-reader/pod-events", agent.PodEvents)
		api.POST("/agents/ebpf/traffic", agent.Traffic)
		api.POST("/agents/sbom", agent.SBOM)

		// ── eBPF Agent (Tetragon, dev_v2 통합) ──
		api.POST("/agents/ebpf/network-flows", ebpf.NetworkFlows)
		api.POST("/agents/ebpf/dns-queries", ebpf.DNSQueries)
		api.POST("/agents/ebpf/process-events", ebpf.ProcessEvents)
		api.GET("/feed/process", ebpf.GetProcessFeed)
		api.GET("/feed/flow", ebpf.GetFlowFeed)
		api.GET("/events", ebpf.GetEvents)

		// ── Edges (Blast Radius 그래프) ──
		api.POST("/edges/compute", edge.Compute)
		api.GET("/edges/clusters/:cluster_name", edge.GetByCluster)
		api.GET("/edges/clusters/:cluster_name/pods/:pod_uid", edge.GetByPod)
		api.POST("/edges/clusters/:cluster_name/identity/compute", edge.ComputeIdentity)
		api.POST("/edges/clusters/:cluster_name/supply-chain/compute", edge.ComputeSupplyChain)
		api.POST("/edges/clusters/:cluster_name/network/compute", edge.ComputeNetwork)
		api.POST("/edges/clusters/:cluster_name/host/compute", edge.ComputeHost)
		api.GET("/topology", edge.GetTopology)
		api.GET("/topology/blast-radius", edge.GetBlastRadius)
		api.GET("/topology/criticality", edge.GetCriticality)
		api.GET("/topology/clusters", edge.GetClusters)
		api.GET("/analysis/blast-radius", analysis.GetBlastRadius)
		api.GET("/analysis/centrality", analysis.GetCentrality)
		api.GET("/analysis/attack-paths", analysis.GetAttackPaths)
		api.POST("/analysis/refresh", analysis.Refresh)

		// ── 기존 Risk Scoring ──
		api.POST("/pods/:pod_id/risk", scoring.ComputeRisk)
		api.GET("/pods/:pod_id/risk/details", scoring.GetRiskDetails)

		// ── 인터넷 노출 (작업 C-1) ──
		api.POST("/scoring/exposure/compute", exposure.Compute)
		api.GET("/scoring/exposure/pods/:pod_uid", exposure.GetByPod)
		api.POST("/scoring/exposure/pods/:pod_uid", exposure.ComputeForPod)
		api.GET("/scoring/exposure/clusters/:cluster_name", exposure.GetByCluster)

		// ── Global CVE Score (작업 B-1) ──
		api.POST("/scoring/global/cves/:cve_id", globalScoring.ComputeCVE)
		api.GET("/scoring/global/cves/:cve_id", globalScoring.GetCVE)
		api.POST("/scoring/global/images", globalScoring.ComputeImage)

		// ── Image Global Cache (작업 B-3a) ──
		api.POST("/scoring/global/images/:digest", imageGlobalCache.ComputeByDigest)
		api.GET("/scoring/global/images/:digest", imageGlobalCache.GetByDigest)

		// ── Attack Path (작업 B-2c) ──
		api.POST("/scoring/attack-path/compute", attackPath.Compute)
		api.GET("/scoring/attack-path/pods/:pod_uid", attackPath.GetByPod)
		api.POST("/scoring/attack-path/pods/:pod_uid", attackPath.ComputeForPod)
		api.GET("/scoring/attack-path/clusters/:cluster_name", attackPath.GetByCluster)

		// ── Local Score (작업 B-2) ──
		api.POST("/scoring/local/compute", localScoring.Compute)
		api.GET("/scoring/local/pods/:pod_uid", localScoring.GetByPod)
		api.POST("/scoring/local/pods/:pod_uid", localScoring.ComputeForPod)
		api.GET("/scoring/local/clusters/:cluster_name", localScoring.GetByCluster)

		// ── Final Score (작업 B-3) ──
		api.POST("/scoring/final/compute", finalScoring.Compute)
		api.GET("/scoring/final/pods/:pod_uid", finalScoring.GetByPod)
		api.POST("/scoring/final/pods/:pod_uid", finalScoring.ComputeForPod)
		api.GET("/scoring/final/clusters/:cluster_name", finalScoring.GetByCluster)
		api.GET("/scoring/breakdown", breakdownH.GetBreakdown)

		// ── Pod Refresh: 단일 Pod의 5개 컴포넌트 통합 ──
		api.POST("/scoring/pods/:pod_uid/refresh", podRefresh.Refresh)

		// ── RBAC Chain (권한상승 분석, fixpoint) ──
		api.POST("/scoring/rbac-chain/compute", rbacChain.Compute)
		api.GET("/scoring/rbac-chain/clusters/:cluster_name", rbacChain.GetByCluster)
		api.GET("/scoring/rbac-chain/clusters/:cluster_name/sa/:namespace/:name", rbacChain.GetSA)

		// ── Toxic Combination (작업 B-4) ──
		api.POST("/scoring/toxic/compute", toxic.Compute)
		api.GET("/scoring/toxic/pods/:pod_uid", toxic.GetByPod)
		api.POST("/scoring/toxic/pods/:pod_uid", toxic.ComputeForPod)
		api.GET("/scoring/toxic/clusters/:cluster_name", toxic.GetByCluster)
		api.GET("/scoring/toxic/rules", toxic.ListRules)

		// ── SBOM Packages (작업 B-5) ──
		// 정적 경로를 동적 경로보다 먼저 등록
		api.GET("/sboms/packages/vulnerabilities/search", packageVuln.SearchByVulnID)
		api.GET("/sboms/packages/vulnerabilities/by-purl", packageVuln.ListByPURL)
		api.GET("/sboms/packages/search", sbomPackage.Search)
		api.POST("/sboms/packages/backfill", sbomPackage.Backfill)
		api.POST("/sboms/packages/extract/:digest", sbomPackage.Extract)

		// ── Dashboard Notifications (Phase 4) ──
		api.GET("/notifications", notif.List)
		api.GET("/notifications/counts", notif.GetCounts)
		api.POST("/notifications/:id/read", notif.MarkRead)
		api.POST("/notifications/read-all", notif.MarkAllRead)
		api.DELETE("/notifications/:id", notif.Dismiss)

		// 동적 경로 (이미지 단위)
		api.POST("/sboms/packages/:digest/vulnerabilities/scan", packageVuln.Scan)
		api.GET("/sboms/packages/:digest/vulnerabilities", packageVuln.ListByImage)
		api.GET("/sboms/packages/:digest", sbomPackage.List)

		// ── ISMS-P ──
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

		// ── GRC Compliance Check (v2) ──
		api.POST("/compliance/checks", grc.CreateCheck)
		api.GET("/compliance/checks", grc.ListChecks)
		api.GET("/compliance/checks/:check_id", grc.GetCheck)
		api.GET("/compliance/checks/:check_id/evidence", grc.ListEvidence)
		api.GET("/rulesets", grc.ListRulesets)
		api.GET("/rulesets/:item_id", grc.GetRuleset)

		// ── Guidelines (지침) ──
		api.POST("/compliance/guidelines", grc.UploadGuideline)
		api.GET("/compliance/guidelines", grc.ListGuidelines)
		api.DELETE("/compliance/guidelines/:id", grc.DeleteGuideline)

		// ── Cloud Environments ──
		api.POST("/compliance/cloud-environments", grc.CreateCloudEnvironments)
		api.GET("/compliance/cloud-environments", grc.ListCloudEnvironments)

		// ── Pod Graph Evaluation ──
		api.POST("/compliance/pod-graph/evaluate", grc.EvaluatePodGraph)
		api.POST("/compliance/pod-graph/evaluate-cluster", grc.EvaluateCluster)
		api.GET("/compliance/pod-graph/evaluations", grc.ListPodGraphEvaluations)
		api.GET("/compliance/pod-graph/evaluations/:eval_id", grc.GetPodGraphEvaluation)
		api.GET("/compliance/pod-graph/rulesets", grc.ListPodRulesets)
		api.GET("/compliance/pod-graph/rulesets/:item_id", grc.GetPodRuleset)

		// ── 통합 클러스터 컴플라이언스 (경로 B+C 병합 → ISMS-P 항목별 위반 자산) ──
		api.POST("/compliance/cluster/evaluate", grc.EvaluateClusterCompliance)

		// ── Compliance Findings (F-X.X.X-K8S-NN) — deprecated, use /compliance/cluster/evaluate ──
		api.GET("/compliance/findings", grc.ListFindings)
		api.POST("/compliance/findings/evaluate-cluster", grc.EvaluateClusterFindings)   // deprecated
		api.GET("/compliance/findings/summaries", grc.ListFindingClusterSummaries)
		api.GET("/compliance/findings/summary", grc.GetFindingsSummary)

		// ── Rule Catalog (변경 2) ──
		api.GET("/compliance/rulesets/catalog", grc.GetRuleCatalog)

		// ── Pod Compliance (변경 3-A: Pod 상세 뷰) ──
		api.GET("/compliance/pods/:pod_name/compliance", grc.GetPodCompliance)

		// ── ISMS-P 항목별 위반 자산 + Pod별 위반 항목 조회 ──
		api.GET("/compliance/items/:item_id/violations", grc.GetISMSPItemViolations)
		api.GET("/compliance/pods/:pod_name/violations", grc.GetPodViolations)

		// ── Backward-compat aliases (deprecated) ──
		api.POST("/compliance/check", grc.CreateCheck)
		api.GET("/compliance/check/:check_id", grc.GetCheck)
		api.GET("/compliance/scans", grc.ListChecks)
		api.GET("/compliance/scans/:check_id", grc.GetCheck)
	}

	return r
}
