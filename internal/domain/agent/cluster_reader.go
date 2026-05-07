package agent

import "time"

// ────────────────────────────────────────────
// Cluster Reader Agent v2 → 8개 엔드포인트 페이로드
// ────────────────────────────────────────────
//
// 모든 페이로드 공통 필드: cluster, snapshot_at
// /api/v1/agents/cluster-reader/{nodes, pods, services, workloads,
//                                  ingresses, network-policies,
//                                  sensitive-resources, rbac}

// ClusterCommon : 모든 cluster-reader 페이로드의 공통 필드
type ClusterCommon struct {
	Cluster    string    `json:"cluster" binding:"required"`
	SnapshotAt time.Time `json:"snapshot_at" binding:"required"`
}

// ────────────────────────────────────────────
// /nodes
// ────────────────────────────────────────────

type ClusterNodesRequest struct {
	ClusterCommon
	Nodes []ClusterNode `json:"nodes" binding:"required,dive"`
}

type ClusterNode struct {
	Name             string                   `json:"name" binding:"required"`
	UID              string                   `json:"uid" binding:"required"`
	InternalIP       string                   `json:"internal_ip"`
	ExternalIP       string                   `json:"external_ip"`
	Labels           map[string]string        `json:"labels"`
	Status           string                   `json:"status"`
	KernelVersion    string                   `json:"kernel_version"`
	OSImage          string                   `json:"os_image"`
	ContainerRuntime string                   `json:"container_runtime"`
	KubeletVersion   string                   `json:"kubelet_version"`
	PodsOnNode       []map[string]interface{} `json:"pods_on_node"`
}

// ────────────────────────────────────────────
// /pods
// ────────────────────────────────────────────

type ClusterPodsRequest struct {
	ClusterCommon
	Namespaces []string     `json:"namespaces"`
	Pods       []ClusterPod `json:"pods" binding:"required,dive"`
}

type ClusterPod struct {
	Name           string                   `json:"name" binding:"required"`
	UID            string                   `json:"uid" binding:"required"`
	Namespace      string                   `json:"namespace" binding:"required"`
	Node           string                   `json:"node"`
	PodIP          string                   `json:"pod_ip"`
	Phase          string                   `json:"phase"`
	RestartCount   int                      `json:"restart_count"`
	ServiceAccount string                   `json:"service_account"`
	Labels         map[string]string        `json:"labels"`
	Annotations    map[string]string        `json:"annotations"`
	Containers     []map[string]interface{} `json:"containers"`
	Volumes        []map[string]interface{} `json:"volumes"`
}

// ────────────────────────────────────────────
// /services
// ────────────────────────────────────────────

type ClusterServicesRequest struct {
	ClusterCommon
	Services []ClusterService `json:"services" binding:"required,dive"`
}

type ClusterService struct {
	Name         string                   `json:"name" binding:"required"`
	Namespace    string                   `json:"namespace" binding:"required"`
	UID          string                   `json:"uid" binding:"required"`
	Type         string                   `json:"type"`
	ClusterIP    string                   `json:"cluster_ip"`
	ExternalIPs  []string                 `json:"external_ips"`
	ExternalName *string                  `json:"external_name"`
	Selector     map[string]string        `json:"selector"`
	Ports        []map[string]interface{} `json:"ports"`
	Endpoints    []map[string]interface{} `json:"endpoints"`
}

// ────────────────────────────────────────────
// /sensitive-resources (Secret + ConfigMap 메타데이터, 내용 X)
// ────────────────────────────────────────────

type ClusterSensitiveResourcesRequest struct {
	ClusterCommon
	Secrets    []ClusterSecret    `json:"secrets"`
	ConfigMaps []ClusterConfigMap `json:"config_maps"`
}

type ClusterSecret struct {
	Name          string         `json:"name" binding:"required"`
	Namespace     string         `json:"namespace" binding:"required"`
	UID           string         `json:"uid" binding:"required"`
	Type          string         `json:"type"`
	MountedByPods []PodReference `json:"mounted_by_pods"`
}

type ClusterConfigMap struct {
	Name          string         `json:"name" binding:"required"`
	Namespace     string         `json:"namespace" binding:"required"`
	UID           string         `json:"uid" binding:"required"`
	MountedByPods []PodReference `json:"mounted_by_pods"`
}

type PodReference struct {
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
}

// ────────────────────────────────────────────
// /ingresses
// ────────────────────────────────────────────

type ClusterIngressesRequest struct {
	ClusterCommon
	Ingresses []ClusterIngress `json:"ingresses" binding:"required,dive"`
}

type ClusterIngress struct {
	Name         string                   `json:"name" binding:"required"`
	Namespace    string                   `json:"namespace" binding:"required"`
	UID          string                   `json:"uid" binding:"required"`
	IngressClass string                   `json:"ingress_class"`
	Rules        []map[string]interface{} `json:"rules"`
	TLS          []map[string]interface{} `json:"tls"`
}

// ────────────────────────────────────────────
// /workloads (Deployment/StatefulSet/DaemonSet/ReplicaSet)
// ────────────────────────────────────────────

type ClusterWorkloadsRequest struct {
	ClusterCommon
	Workloads []ClusterWorkload `json:"workloads" binding:"required,dive"`
}

type ClusterWorkload struct {
	Kind              string                  `json:"kind" binding:"required"`
	Name              string                  `json:"name" binding:"required"`
	Namespace         string                  `json:"namespace" binding:"required"`
	UID               string                  `json:"uid" binding:"required"`
	ReplicasDesired   int                     `json:"replicas_desired"`
	ReplicasReady     int                     `json:"replicas_ready"`
	ReplicasAvailable int                     `json:"replicas_available"`
	Selector          map[string]interface{}  `json:"selector"`
	TemplateLabels    map[string]string       `json:"template_labels"`
	Containers        []WorkloadContainerInfo `json:"containers"`
}

type WorkloadContainerInfo struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// ────────────────────────────────────────────
// /network-policies
// ────────────────────────────────────────────

type ClusterNetworkPoliciesRequest struct {
	ClusterCommon
	NetworkPolicies []ClusterNetworkPolicy `json:"network_policies" binding:"required,dive"`
}

type ClusterNetworkPolicy struct {
	Name         string                   `json:"name" binding:"required"`
	Namespace    string                   `json:"namespace" binding:"required"`
	UID          string                   `json:"uid" binding:"required"`
	PodSelector  map[string]interface{}   `json:"pod_selector"`
	PolicyTypes  []string                 `json:"policy_types"`
	IngressRules []map[string]interface{} `json:"ingress_rules"`
	EgressRules  []map[string]interface{} `json:"egress_rules"`
}

// ────────────────────────────────────────────
// /rbac (5종 RBAC 리소스)
// ────────────────────────────────────────────

type ClusterRBACRequest struct {
	ClusterCommon
	ServiceAccounts     []RBACServiceAccount     `json:"service_accounts"`
	ClusterRoles        []RBACClusterRole        `json:"cluster_roles"`
	Roles               []RBACRole               `json:"roles"`
	ClusterRoleBindings []RBACClusterRoleBinding `json:"cluster_role_bindings"`
	RoleBindings        []RBACRoleBinding        `json:"role_bindings"`
}

type RBACServiceAccount struct {
	Name      string   `json:"name" binding:"required"`
	Namespace string   `json:"namespace" binding:"required"`
	UID       string   `json:"uid" binding:"required"`
	Secrets   []string `json:"secrets"`
}

type RBACClusterRole struct {
	Name  string                   `json:"name" binding:"required"`
	UID   string                   `json:"uid" binding:"required"`
	Rules []map[string]interface{} `json:"rules"`
}

type RBACRole struct {
	Name      string                   `json:"name" binding:"required"`
	Namespace string                   `json:"namespace" binding:"required"`
	UID       string                   `json:"uid" binding:"required"`
	Rules     []map[string]interface{} `json:"rules"`
}

type RBACClusterRoleBinding struct {
	Name     string                   `json:"name" binding:"required"`
	UID      string                   `json:"uid" binding:"required"`
	RoleRef  map[string]interface{}   `json:"role_ref"`
	Subjects []map[string]interface{} `json:"subjects"`
}

type RBACRoleBinding struct {
	Name      string                   `json:"name" binding:"required"`
	Namespace string                   `json:"namespace" binding:"required"`
	UID       string                   `json:"uid" binding:"required"`
	RoleRef   map[string]interface{}   `json:"role_ref"`
	Subjects  []map[string]interface{} `json:"subjects"`
}
