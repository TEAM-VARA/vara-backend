package service

import (
	"encoding/json"

	"github.com/vara/backend/internal/repository/postgres"
)

// ClusterEvalRequest is the API input for cluster-wide pod evaluation.
type ClusterEvalRequest struct {
	CompanyID   string `json:"company_id"`
	ClusterName string `json:"cluster_name"`
	Namespace   string `json:"namespace,omitempty"` // optional: filter by namespace
	Limit       int    `json:"limit,omitempty"`     // default 50, max 200
	Offset      int    `json:"offset,omitempty"`
}

// ClusterEvalResultItem is a summary of a single pod evaluation.
type ClusterEvalResultItem struct {
	PodName        string `json:"pod_name"`
	Namespace      string `json:"namespace"`
	OverallVerdict string `json:"overall_verdict"`
	TotalRules     int    `json:"total_rules"`
	Passed         int    `json:"passed"`
	Failed         int    `json:"failed"`
	Skipped        int    `json:"skipped"`
	ID             int64  `json:"id"`
}

// ClusterEvalResult is the response for cluster-wide evaluation.
type ClusterEvalResult struct {
	ClusterName    string                  `json:"cluster_name"`
	SnapshotAt     string                  `json:"snapshot_at"`
	TotalPodsScope int                     `json:"total_pods_in_scope"`
	Evaluated      int                     `json:"evaluated"`
	Results        []ClusterEvalResultItem `json:"results"`
}

// AssembleClusterPodGraph converts a DB pod row + related resources into PodGraphRequest.
func AssembleClusterPodGraph(
	companyID, clusterName string,
	pod postgres.ClusterPodRow,
	related *postgres.ClusterRelatedRows,
) PodGraphRequest {
	// Build pod map (K8s Pod-like structure)
	var labels map[string]any
	_ = json.Unmarshal(pod.Labels, &labels)
	if labels == nil {
		labels = map[string]any{}
	}

	var annotations map[string]any
	_ = json.Unmarshal(pod.Annotations, &annotations)
	if annotations == nil {
		annotations = map[string]any{}
	}

	var containers []any
	_ = json.Unmarshal(pod.Containers, &containers)
	if containers == nil {
		containers = []any{}
	}

	var volumes []any
	_ = json.Unmarshal(pod.Volumes, &volumes)
	if volumes == nil {
		volumes = []any{}
	}

	podMap := map[string]any{
		"metadata": map[string]any{
			"name":        pod.Name,
			"namespace":   pod.Namespace,
			"labels":      labels,
			"annotations": annotations,
		},
		"spec": map[string]any{
			"serviceAccountName":           pod.ServiceAccount,
			"containers":                   containers,
			"volumes":                      volumes,
			"hostNetwork":                  pod.HostNetwork,
			"hostPID":                      pod.HostPID,
			"hostIPC":                      pod.HostIPC,
			"automountServiceAccountToken": pod.AutomountSAToken, // *bool: nil=미설정(기본 마운트), 3상태 유지
		},
	}

	// Build namespace map
	nsLabels := map[string]any{}
	nsMap := map[string]any{
		"metadata": map[string]any{
			"name":   pod.Namespace,
			"labels": nsLabels,
		},
	}

	// Build namespaces_in_cluster
	var namespacesInCluster []map[string]any
	for _, ns := range related.Namespaces {
		namespacesInCluster = append(namespacesInCluster, map[string]any{
			"metadata": map[string]any{
				"name":   ns,
				"labels": map[string]any{},
			},
		})
	}
	if namespacesInCluster == nil {
		namespacesInCluster = []map[string]any{}
	}

	// Build EKS cluster info
	eksCluster := map[string]any{
		"name":                clusterName,
		"authentication_mode": related.EKSAuthenticationMode,
	}

	return PodGraphRequest{
		CompanyID:   companyID,
		ClusterName: clusterName,
		Pod:         podMap,
		RelatedResources: PodRelatedResources{
			Namespace:           nsMap,
			Services:            emptyIfNil(related.Services),
			Ingresses:           emptyIfNil(related.Ingresses),
			NetworkPolicies:     emptyIfNil(related.NetworkPolicies),
			ConfigMaps:          emptyIfNil(related.ConfigMaps),
			ClusterRoleBindings: emptyIfNil(related.ClusterRoleBindings),
			RoleBindings:        emptyIfNil(related.RoleBindings),
			ClusterRoles:        emptyIfNil(related.ClusterRoles),
			Roles:               emptyIfNil(related.Roles),
			ServiceAccounts:     emptyIfNil(related.ServiceAccounts),
			Workloads:           emptyIfNil(related.Workloads),
			Secrets:             emptyIfNil(related.Secrets),
			Nodes:               emptyIfNil(related.Nodes),
			EBPFProcessEvents:   emptyIfNil(related.EBPFProcessEvents),
			NamespacesInCluster: namespacesInCluster,
			EKSCluster:          eksCluster,
		},
	}
}

func emptyIfNil(s []map[string]any) []map[string]any {
	if s == nil {
		return []map[string]any{}
	}
	return s
}
