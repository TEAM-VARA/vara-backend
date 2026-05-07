package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/agent"
	"github.com/vara/backend/internal/repository/postgres"
)

// ────────────────────────────────────────────
// Cluster Reader Agent v2 → 8개 엔드포인트
// ────────────────────────────────────────────
//
// /api/v1/agents/cluster-reader/{nodes, pods, services, workloads,
//                                 ingresses, network-policies,
//                                 sensitive-resources, rbac}
//
// 공통 페이로드:
//   {
//     "cluster": "vara-test-cluster",
//     "snapshot_at": "2026-05-03T11:46:45Z",
//     "<resource>": [...]
//   }

type ClusterReaderHandler struct {
	repo *postgres.ClusterReaderRepo
}

func NewClusterReader(repo *postgres.ClusterReaderRepo) *ClusterReaderHandler {
	return &ClusterReaderHandler{repo: repo}
}

// Nodes : POST /api/v1/agents/cluster-reader/nodes
//
// 노드 정보 + 노드 위 파드 분포 수신. 주기 1분.
func (h *ClusterReaderHandler) Nodes(c *gin.Context) {
	var req agent.ClusterNodesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saved, err := h.repo.UpsertNodes(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader nodes failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":  req.Cluster,
		"received": len(req.Nodes),
		"saved":    saved,
	})
}

// Pods : POST /api/v1/agents/cluster-reader/pods
//
// 파드 + 네임스페이스 정보 수신. 주기 30초.
func (h *ClusterReaderHandler) Pods(c *gin.Context) {
	var req agent.ClusterPodsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	podsSaved, nsSaved, err := h.repo.UpsertPods(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader pods failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":          req.Cluster,
		"pods_received":    len(req.Pods),
		"pods_saved":       podsSaved,
		"namespaces_saved": nsSaved,
	})
}

// Services : POST /api/v1/agents/cluster-reader/services
//
// Service + Endpoints 매핑 정보 수신. 주기 1분.
func (h *ClusterReaderHandler) Services(c *gin.Context) {
	var req agent.ClusterServicesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saved, err := h.repo.UpsertServices(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader services failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":  req.Cluster,
		"received": len(req.Services),
		"saved":    saved,
	})
}

// Sensitive : POST /api/v1/agents/cluster-reader/sensitive-resources
//
// Secret + ConfigMap 메타데이터 수신 (내용 X). 주기 5분.
func (h *ClusterReaderHandler) Sensitive(c *gin.Context) {
	var req agent.ClusterSensitiveResourcesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	secretsSaved, configMapsSaved, err := h.repo.UpsertSensitiveResources(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader sensitive-resources failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":             req.Cluster,
		"secrets_received":    len(req.Secrets),
		"secrets_saved":       secretsSaved,
		"configmaps_received": len(req.ConfigMaps),
		"configmaps_saved":    configMapsSaved,
	})
}

// Ingresses : POST /api/v1/agents/cluster-reader/ingresses
//
// Ingress 정보 (host/path/TLS) 수신. 주기 1분.
func (h *ClusterReaderHandler) Ingresses(c *gin.Context) {
	var req agent.ClusterIngressesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saved, err := h.repo.UpsertIngresses(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader ingresses failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":  req.Cluster,
		"received": len(req.Ingresses),
		"saved":    saved,
	})
}

// Workloads : POST /api/v1/agents/cluster-reader/workloads
//
// Deployment/StatefulSet/DaemonSet/ReplicaSet 일괄 수신.
func (h *ClusterReaderHandler) Workloads(c *gin.Context) {
	var req agent.ClusterWorkloadsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saved, err := h.repo.UpsertWorkloads(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader workloads failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":  req.Cluster,
		"received": len(req.Workloads),
		"saved":    saved,
	})
}

// NetworkPolicies : POST /api/v1/agents/cluster-reader/network-policies
//
// NetworkPolicy 정보 (pod_selector, ingress/egress 규칙) 수신. 주기 5분.
func (h *ClusterReaderHandler) NetworkPolicies(c *gin.Context) {
	var req agent.ClusterNetworkPoliciesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saved, err := h.repo.UpsertNetworkPolicies(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader network-policies failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":  req.Cluster,
		"received": len(req.NetworkPolicies),
		"saved":    saved,
	})
}

// RBAC : POST /api/v1/agents/cluster-reader/rbac
//
// 5종 RBAC 리소스 일괄 수신 (SA, ClusterRole, Role, ClusterRoleBinding, RoleBinding).
// 주기 5분.
func (h *ClusterReaderHandler) RBAC(c *gin.Context) {
	var req agent.ClusterRBACRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saSaved, crSaved, rSaved, crbSaved, rbSaved, err := h.repo.UpsertRBAC(ctx, req)
	if err != nil {
		fmt.Printf("warn: cluster-reader rbac failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster":                     req.Cluster,
		"service_accounts_saved":      saSaved,
		"cluster_roles_saved":         crSaved,
		"roles_saved":                 rSaved,
		"cluster_role_bindings_saved": crbSaved,
		"role_bindings_saved":         rbSaved,
	})
}
