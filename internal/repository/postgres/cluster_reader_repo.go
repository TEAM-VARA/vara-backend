// GRC 보조: Cluster Reader 에이전트가 수집한 K8s 리소스(cluster_nodes, cluster_pods,
// cluster_services, cluster_workloads, cluster_ingresses, cluster_network_policies,
// cluster_rbac, cluster_sensitive_resources 등 12개 테이블)를 UPSERT 저장.
// GRC Finding 평가 시 ClusterSnapshot을 구성하는 데이터 소스이며,
// PodGraph 평가 시 Pod 단위 관련 리소스 조회에도 사용된다.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/agent"
)

// ClusterReaderRepo : Cluster Reader Agent 데이터를 RDS에 저장
type ClusterReaderRepo struct {
	pg *pgxpool.Pool
}

func NewClusterReaderRepo(pg *pgxpool.Pool) *ClusterReaderRepo {
	return &ClusterReaderRepo{pg: pg}
}

// ────────────────────────────────────────────
// /nodes
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertNodes(ctx context.Context, req agent.ClusterNodesRequest) (int, error) {
	if len(req.Nodes) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO cluster_nodes (
			cluster_name, snapshot_at, node_uid, name,
			internal_ip, external_ip, status,
			kernel_version, os_image, container_runtime, kubelet_version,
			labels, pods_on_node
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (cluster_name, snapshot_at, node_uid) DO UPDATE SET
			name              = EXCLUDED.name,
			internal_ip       = EXCLUDED.internal_ip,
			external_ip       = EXCLUDED.external_ip,
			status            = EXCLUDED.status,
			kernel_version    = EXCLUDED.kernel_version,
			os_image          = EXCLUDED.os_image,
			container_runtime = EXCLUDED.container_runtime,
			kubelet_version   = EXCLUDED.kubelet_version,
			labels            = EXCLUDED.labels,
			pods_on_node      = EXCLUDED.pods_on_node
	`

	saved := 0
	for _, n := range req.Nodes {
		labelsJSON, _ := json.Marshal(n.Labels)
		podsOnNodeJSON, _ := json.Marshal(n.PodsOnNode)

		_, err := tx.Exec(ctx, q,
			req.Cluster, req.SnapshotAt, n.UID, n.Name,
			n.InternalIP, n.ExternalIP, n.Status,
			n.KernelVersion, n.OSImage, n.ContainerRuntime, n.KubeletVersion,
			labelsJSON, podsOnNodeJSON,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert node %s: %w", n.Name, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// ────────────────────────────────────────────
// /pods (namespaces + pods 한 트랜잭션)
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertPods(ctx context.Context, req agent.ClusterPodsRequest) (int, int, error) {
	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. namespaces
	const nsQ = `
		INSERT INTO cluster_namespaces (cluster_name, snapshot_at, namespace)
		VALUES ($1, $2, $3)
		ON CONFLICT (cluster_name, snapshot_at, namespace) DO NOTHING
	`
	for _, ns := range req.Namespaces {
		if _, err := tx.Exec(ctx, nsQ, req.Cluster, req.SnapshotAt, ns); err != nil {
			return 0, 0, fmt.Errorf("insert namespace %s: %w", ns, err)
		}
	}

	// 2. pods
	const podQ = `
		INSERT INTO cluster_pods (
			cluster_name, snapshot_at, pod_uid, name, namespace,
			node, pod_ip, phase, restart_count, service_account,
			labels, annotations, containers, volumes,
			host_network, started_at, host_pid, host_ipc, automount_sa_token
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
		ON CONFLICT (cluster_name, snapshot_at, pod_uid) DO UPDATE SET
			phase             = EXCLUDED.phase,
			restart_count     = EXCLUDED.restart_count,
			pod_ip            = EXCLUDED.pod_ip,
			containers        = EXCLUDED.containers,
			volumes           = EXCLUDED.volumes,
			host_network      = EXCLUDED.host_network,
			started_at        = EXCLUDED.started_at,
			host_pid          = EXCLUDED.host_pid,
			host_ipc          = EXCLUDED.host_ipc,
			automount_sa_token = EXCLUDED.automount_sa_token
	`

	saved := 0
	for _, p := range req.Pods {
		labelsJSON, _ := json.Marshal(p.Labels)
		annotationsJSON, _ := json.Marshal(p.Annotations)
		containersJSON, _ := json.Marshal(p.Containers)
		volumesJSON, _ := json.Marshal(p.Volumes)

		_, err := tx.Exec(ctx, podQ,
			req.Cluster, req.SnapshotAt, p.UID, p.Name, p.Namespace,
			p.Node, p.PodIP, p.Phase, p.RestartCount, p.ServiceAccount,
			labelsJSON, annotationsJSON, containersJSON, volumesJSON,
			p.HostNetwork, p.StartedAt, p.HostPID, p.HostIPC, p.AutomountSAToken,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("upsert pod %s: %w", p.Name, err)
		}
		saved++
	}

	// pod_master reconcile (soft delete)
	const pmUpsert = `
		INSERT INTO pod_master (
			cluster_name, pod_uid, name, namespace, node,
			service_account, phase, restart_count, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (cluster_name, pod_uid) DO UPDATE SET
			name            = EXCLUDED.name,
			namespace       = EXCLUDED.namespace,
			node            = EXCLUDED.node,
			service_account = EXCLUDED.service_account,
			phase           = EXCLUDED.phase,
			restart_count   = EXCLUDED.restart_count,
			last_seen_at    = EXCLUDED.last_seen_at,
			deleted_at      = NULL
	`
	for _, p := range req.Pods {
		if _, err := tx.Exec(ctx, pmUpsert,
			req.Cluster, p.UID, p.Name, p.Namespace, p.Node,
			p.ServiceAccount, p.Phase, p.RestartCount, req.SnapshotAt,
		); err != nil {
			return 0, 0, fmt.Errorf("pod_master upsert %s: %w", p.Name, err)
		}
	}

	if len(req.Pods) > 0 {
		var aliveCount int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM pod_master WHERE cluster_name = $1 AND deleted_at IS NULL`,
			req.Cluster,
		).Scan(&aliveCount); err != nil {
			return 0, 0, fmt.Errorf("pod_master alive count: %w", err)
		}
		if aliveCount == 0 || len(req.Pods) >= aliveCount/2 {
			const pmDelete = `
				UPDATE pod_master
				SET deleted_at = $1
				WHERE cluster_name = $2
				  AND deleted_at IS NULL
				  AND last_seen_at < $1::timestamptz - INTERVAL '90 seconds'
			`
			if _, err := tx.Exec(ctx, pmDelete, req.SnapshotAt, req.Cluster); err != nil {
				return 0, 0, fmt.Errorf("pod_master mark deleted: %w", err)
			}
		} else {
			fmt.Printf("warn: pod_master reconcile skip (collection anomaly? got %d < alive %d)\n",
				len(req.Pods), aliveCount)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, len(req.Namespaces), nil
}

// ────────────────────────────────────────────
// /services
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertServices(ctx context.Context, req agent.ClusterServicesRequest) (int, error) {
	if len(req.Services) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO cluster_services (
			cluster_name, snapshot_at, service_uid, name, namespace,
			type, cluster_ip, external_name, external_ips,
			selector, ports, endpoints
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (cluster_name, snapshot_at, service_uid) DO UPDATE SET
			type         = EXCLUDED.type,
			cluster_ip   = EXCLUDED.cluster_ip,
			ports        = EXCLUDED.ports,
			endpoints    = EXCLUDED.endpoints
	`

	saved := 0
	for _, s := range req.Services {
		var externalName interface{} = nil
		if s.ExternalName != nil {
			externalName = *s.ExternalName
		}

		externalIPsJSON, _ := json.Marshal(s.ExternalIPs)
		selectorJSON, _ := json.Marshal(s.Selector)
		portsJSON, _ := json.Marshal(s.Ports)
		endpointsJSON, _ := json.Marshal(s.Endpoints)

		_, err := tx.Exec(ctx, q,
			req.Cluster, req.SnapshotAt, s.UID, s.Name, s.Namespace,
			s.Type, s.ClusterIP, externalName, externalIPsJSON,
			selectorJSON, portsJSON, endpointsJSON,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert service %s: %w", s.Name, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// ────────────────────────────────────────────
// /sensitive-resources (Secret + ConfigMap)
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertSensitiveResources(ctx context.Context, req agent.ClusterSensitiveResourcesRequest) (int, int, error) {
	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Secrets
	const secretQ = `
		INSERT INTO cluster_secrets (
			cluster_name, snapshot_at, secret_uid, name, namespace,
			type, mounted_by_pods
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
		ON CONFLICT (cluster_name, snapshot_at, secret_uid) DO UPDATE SET
			type            = EXCLUDED.type,
			mounted_by_pods = EXCLUDED.mounted_by_pods
	`

	secretsSaved := 0
	for _, s := range req.Secrets {
		mountedJSON, _ := json.Marshal(s.MountedByPods)
		_, err := tx.Exec(ctx, secretQ,
			req.Cluster, req.SnapshotAt, s.UID, s.Name, s.Namespace,
			s.Type, mountedJSON,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("upsert secret %s: %w", s.Name, err)
		}
		secretsSaved++
	}

	// 2. ConfigMaps
	const cmQ = `
		INSERT INTO cluster_configmaps (
			cluster_name, snapshot_at, configmap_uid, name, namespace,
			mounted_by_pods
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)
		ON CONFLICT (cluster_name, snapshot_at, configmap_uid) DO UPDATE SET
			mounted_by_pods = EXCLUDED.mounted_by_pods
	`

	configMapsSaved := 0
	for _, cm := range req.ConfigMaps {
		mountedJSON, _ := json.Marshal(cm.MountedByPods)
		_, err := tx.Exec(ctx, cmQ,
			req.Cluster, req.SnapshotAt, cm.UID, cm.Name, cm.Namespace,
			mountedJSON,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("upsert configmap %s: %w", cm.Name, err)
		}
		configMapsSaved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("tx commit: %w", err)
	}
	return secretsSaved, configMapsSaved, nil
}

// ────────────────────────────────────────────
// /ingresses
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertIngresses(ctx context.Context, req agent.ClusterIngressesRequest) (int, error) {
	if len(req.Ingresses) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO cluster_ingresses (
			cluster_name, snapshot_at, ingress_uid, name, namespace,
			ingress_class, rules, tls, annotations
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (cluster_name, snapshot_at, ingress_uid) DO UPDATE SET
			ingress_class = EXCLUDED.ingress_class,
			rules         = EXCLUDED.rules,
			tls           = EXCLUDED.tls,
			annotations   = EXCLUDED.annotations
	`

	saved := 0
	for _, ing := range req.Ingresses {
		rulesJSON, _ := json.Marshal(ing.Rules)
		tlsJSON, _ := json.Marshal(ing.TLS)
		annotationsJSON, _ := json.Marshal(ing.Annotations)
		_, err := tx.Exec(ctx, q,
			req.Cluster, req.SnapshotAt, ing.UID, ing.Name, ing.Namespace,
			ing.IngressClass, rulesJSON, tlsJSON, annotationsJSON,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert ingress %s: %w", ing.Name, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// ────────────────────────────────────────────
// /workloads
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertWorkloads(ctx context.Context, req agent.ClusterWorkloadsRequest) (int, error) {
	if len(req.Workloads) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO cluster_workloads (
			cluster_name, snapshot_at, workload_uid, kind, name, namespace,
			replicas_desired, replicas_ready, replicas_available,
			selector, template_labels, containers
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (cluster_name, snapshot_at, workload_uid) DO UPDATE SET
			replicas_desired   = EXCLUDED.replicas_desired,
			replicas_ready     = EXCLUDED.replicas_ready,
			replicas_available = EXCLUDED.replicas_available,
			selector           = EXCLUDED.selector,
			template_labels    = EXCLUDED.template_labels,
			containers         = EXCLUDED.containers
	`

	saved := 0
	for _, w := range req.Workloads {
		selectorJSON, _ := json.Marshal(w.Selector)
		templateLabelsJSON, _ := json.Marshal(w.TemplateLabels)
		containersJSON, _ := json.Marshal(w.Containers)

		_, err := tx.Exec(ctx, q,
			req.Cluster, req.SnapshotAt, w.UID, w.Kind, w.Name, w.Namespace,
			w.ReplicasDesired, w.ReplicasReady, w.ReplicasAvailable,
			selectorJSON, templateLabelsJSON, containersJSON,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert workload %s/%s: %w", w.Kind, w.Name, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// ────────────────────────────────────────────
// /network-policies
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertNetworkPolicies(ctx context.Context, req agent.ClusterNetworkPoliciesRequest) (int, error) {
	if len(req.NetworkPolicies) == 0 {
		return 0, nil
	}

	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO cluster_network_policies (
			cluster_name, snapshot_at, policy_uid, name, namespace,
			pod_selector, policy_types, ingress_rules, egress_rules
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (cluster_name, snapshot_at, policy_uid) DO UPDATE SET
			pod_selector  = EXCLUDED.pod_selector,
			policy_types  = EXCLUDED.policy_types,
			ingress_rules = EXCLUDED.ingress_rules,
			egress_rules  = EXCLUDED.egress_rules
	`

	saved := 0
	for _, np := range req.NetworkPolicies {
		podSelectorJSON, _ := json.Marshal(np.PodSelector)

		policyTypes := np.PolicyTypes
		if policyTypes == nil {
			policyTypes = []string{}
		}
		policyTypesJSON, _ := json.Marshal(policyTypes)

		ingressRules := np.IngressRules
		if ingressRules == nil {
			ingressRules = []map[string]interface{}{}
		}
		ingressRulesJSON, _ := json.Marshal(ingressRules)

		egressRules := np.EgressRules
		if egressRules == nil {
			egressRules = []map[string]interface{}{}
		}
		egressRulesJSON, _ := json.Marshal(egressRules)

		_, err := tx.Exec(ctx, q,
			req.Cluster, req.SnapshotAt, np.UID, np.Name, np.Namespace,
			podSelectorJSON, policyTypesJSON, ingressRulesJSON, egressRulesJSON,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert network policy %s: %w", np.Name, err)
		}
		saved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return saved, nil
}

// ────────────────────────────────────────────
// /rbac (5종 RBAC 한 트랜잭션)
// ────────────────────────────────────────────

func (r *ClusterReaderRepo) UpsertRBAC(ctx context.Context, req agent.ClusterRBACRequest) (int, int, int, int, int, error) {
	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	saSaved, crSaved, rSaved, crbSaved, rbSaved := 0, 0, 0, 0, 0

	// 1. ServiceAccounts
	const saQ = `
		INSERT INTO cluster_service_accounts (
			cluster_name, snapshot_at, sa_uid, name, namespace, secrets, automount_sa_token
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (cluster_name, snapshot_at, sa_uid) DO UPDATE SET
			secrets = EXCLUDED.secrets,
			automount_sa_token = EXCLUDED.automount_sa_token
	`
	for _, sa := range req.ServiceAccounts {
		secrets := sa.Secrets
		if secrets == nil {
			secrets = []string{}
		}
		secretsJSON, _ := json.Marshal(secrets)
		_, err := tx.Exec(ctx, saQ,
			req.Cluster, req.SnapshotAt, sa.UID, sa.Name, sa.Namespace, secretsJSON, sa.AutomountSAToken)
		if err != nil {
			return 0, 0, 0, 0, 0, fmt.Errorf("upsert sa %s: %w", sa.Name, err)
		}
		saSaved++
	}

	// 2. ClusterRoles
	const crQ = `
		INSERT INTO cluster_cluster_roles (
			cluster_name, snapshot_at, role_uid, name, rules
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (cluster_name, snapshot_at, role_uid) DO UPDATE SET
			rules = EXCLUDED.rules
	`
	for _, cr := range req.ClusterRoles {
		rules := cr.Rules
		if rules == nil {
			rules = []map[string]interface{}{}
		}
		rulesJSON, _ := json.Marshal(rules)
		_, err := tx.Exec(ctx, crQ,
			req.Cluster, req.SnapshotAt, cr.UID, cr.Name, rulesJSON)
		if err != nil {
			return 0, 0, 0, 0, 0, fmt.Errorf("upsert cr %s: %w", cr.Name, err)
		}
		crSaved++
	}

	// 3. Roles
	const rQ = `
		INSERT INTO cluster_roles (
			cluster_name, snapshot_at, role_uid, name, namespace, rules
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (cluster_name, snapshot_at, role_uid) DO UPDATE SET
			rules = EXCLUDED.rules
	`
	for _, role := range req.Roles {
		rules := role.Rules
		if rules == nil {
			rules = []map[string]interface{}{}
		}
		rulesJSON, _ := json.Marshal(rules)
		_, err := tx.Exec(ctx, rQ,
			req.Cluster, req.SnapshotAt, role.UID, role.Name, role.Namespace, rulesJSON)
		if err != nil {
			return 0, 0, 0, 0, 0, fmt.Errorf("upsert role %s: %w", role.Name, err)
		}
		rSaved++
	}

	// 4. ClusterRoleBindings
	const crbQ = `
		INSERT INTO cluster_cluster_role_bindings (
			cluster_name, snapshot_at, binding_uid, name, role_ref, subjects
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (cluster_name, snapshot_at, binding_uid) DO UPDATE SET
			role_ref = EXCLUDED.role_ref,
			subjects = EXCLUDED.subjects
	`
	for _, crb := range req.ClusterRoleBindings {
		roleRef := crb.RoleRef
		if roleRef == nil {
			roleRef = map[string]interface{}{}
		}
		roleRefJSON, _ := json.Marshal(roleRef)

		subjects := crb.Subjects
		if subjects == nil {
			subjects = []map[string]interface{}{}
		}
		subjectsJSON, _ := json.Marshal(subjects)

		_, err := tx.Exec(ctx, crbQ,
			req.Cluster, req.SnapshotAt, crb.UID, crb.Name, roleRefJSON, subjectsJSON)
		if err != nil {
			return 0, 0, 0, 0, 0, fmt.Errorf("upsert crb %s: %w", crb.Name, err)
		}
		crbSaved++
	}

	// 5. RoleBindings
	const rbQ = `
		INSERT INTO cluster_role_bindings (
			cluster_name, snapshot_at, binding_uid, name, namespace, role_ref, subjects
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (cluster_name, snapshot_at, binding_uid) DO UPDATE SET
			role_ref = EXCLUDED.role_ref,
			subjects = EXCLUDED.subjects
	`
	for _, rb := range req.RoleBindings {
		roleRef := rb.RoleRef
		if roleRef == nil {
			roleRef = map[string]interface{}{}
		}
		roleRefJSON, _ := json.Marshal(roleRef)

		subjects := rb.Subjects
		if subjects == nil {
			subjects = []map[string]interface{}{}
		}
		subjectsJSON, _ := json.Marshal(subjects)

		_, err := tx.Exec(ctx, rbQ,
			req.Cluster, req.SnapshotAt, rb.UID, rb.Name, rb.Namespace, roleRefJSON, subjectsJSON)
		if err != nil {
			return 0, 0, 0, 0, 0, fmt.Errorf("upsert rb %s: %w", rb.Name, err)
		}
		rbSaved++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("tx commit: %w", err)
	}
	return saSaved, crSaved, rSaved, crbSaved, rbSaved, nil
}

// ════════════════════════════════════════════
// READ 메서드 (cluster_* → PodGraphRequest 매핑용)
// ════════════════════════════════════════════

// ClusterPodRow is a DB row from cluster_pods.
type ClusterPodRow struct {
	Name           string
	Namespace      string
	Node           string
	ServiceAccount string
	Labels         json.RawMessage
	Annotations    json.RawMessage
	Containers     json.RawMessage
	Volumes        json.RawMessage
	HostNetwork    bool
	HostPID        bool
	HostIPC        bool
}

// GetLatestSnapshotAt returns the most recent snapshot_at for a cluster.
func (r *ClusterReaderRepo) GetLatestSnapshotAt(ctx context.Context, clusterName string) (time.Time, error) {
	var snapshotAt time.Time
	err := r.pg.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1`,
		clusterName,
	).Scan(&snapshotAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("get latest snapshot: %w", err)
	}
	if snapshotAt.IsZero() {
		return time.Time{}, fmt.Errorf("no snapshots found for cluster %s", clusterName)
	}
	return snapshotAt, nil
}

// ListPods returns pods for a cluster/snapshot, optionally filtered by namespace.
func (r *ClusterReaderRepo) ListPods(
	ctx context.Context,
	clusterName string,
	snapshotAt time.Time,
	namespace string,
	limit, offset int,
) ([]ClusterPodRow, int, error) {
	// Count total
	countQ := `SELECT COUNT(*) FROM cluster_pods WHERE cluster_name = $1 AND snapshot_at = $2`
	countArgs := []any{clusterName, snapshotAt}
	if namespace != "" {
		countQ += ` AND namespace = $3`
		countArgs = append(countArgs, namespace)
	}

	var total int
	if err := r.pg.QueryRow(ctx, countQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count pods: %w", err)
	}

	// Fetch rows
	q := `SELECT name, namespace, node, service_account, labels, annotations, containers, volumes, COALESCE(host_network, false), COALESCE(host_pid, false), COALESCE(host_ipc, false)
		  FROM cluster_pods WHERE cluster_name = $1 AND snapshot_at = $2`
	args := []any{clusterName, snapshotAt}
	argIdx := 3

	if namespace != "" {
		q += fmt.Sprintf(` AND namespace = $%d`, argIdx)
		args = append(args, namespace)
		argIdx++
	}

	q += fmt.Sprintf(` ORDER BY namespace, name LIMIT $%d OFFSET $%d`, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.pg.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query pods: %w", err)
	}
	defer rows.Close()

	var pods []ClusterPodRow
	for rows.Next() {
		var p ClusterPodRow
		var node, sa *string
		if err := rows.Scan(&p.Name, &p.Namespace, &node, &sa,
			&p.Labels, &p.Annotations, &p.Containers, &p.Volumes, &p.HostNetwork, &p.HostPID, &p.HostIPC); err != nil {
			return nil, 0, fmt.Errorf("scan pod: %w", err)
		}
		if node != nil {
			p.Node = *node
		}
		if sa != nil {
			p.ServiceAccount = *sa
		}
		pods = append(pods, p)
	}
	return pods, total, nil
}

// PodDetailRow is a DB row from cluster_pods with full metadata for the pod detail endpoint.
type PodDetailRow struct {
	PodUID         string
	Name           string
	Namespace      string
	Node           string
	PodIP          string
	Phase          string
	ServiceAccount string
	Labels         json.RawMessage
	HostNetwork    bool
	StartedAt      *time.Time
}

// GetPodByName returns pod metadata + pod_uid from the latest snapshot.
func (r *ClusterReaderRepo) GetPodByName(ctx context.Context, clusterName, namespace, podName string) (*PodDetailRow, error) {
	q := `SELECT pod_uid, name, namespace, COALESCE(node,''), COALESCE(pod_ip,''),
	             COALESCE(phase,''), COALESCE(service_account,''), COALESCE(labels,'{}'),
	             COALESCE(host_network, false), started_at
	        FROM cluster_pods
	       WHERE cluster_name = $1
	         AND snapshot_at = (SELECT MAX(snapshot_at) FROM cluster_pods WHERE cluster_name = $1)
	         AND name = $2`
	args := []any{clusterName, podName}
	argIdx := 3
	if namespace != "" {
		q += fmt.Sprintf(` AND namespace = $%d`, argIdx)
		args = append(args, namespace)
	}
	q += ` LIMIT 1`

	var p PodDetailRow
	err := r.pg.QueryRow(ctx, q, args...).Scan(
		&p.PodUID, &p.Name, &p.Namespace, &p.Node, &p.PodIP,
		&p.Phase, &p.ServiceAccount, &p.Labels,
		&p.HostNetwork, &p.StartedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get pod by name: %w", err)
	}
	return &p, nil
}

// LookupPodByUID resolves a pod UID (full UUID or short hex prefix) to its
// name+namespace via pod_master. 프론트가 pod을 UID로 식별하는 경우 GRC 조회를
// 위해 이름으로 변환한다. clusterName이 비면 클러스터 무관 조회. found=false면 미발견.
func (r *ClusterReaderRepo) LookupPodByUID(ctx context.Context, clusterName, uid string) (name, namespace string, found bool) {
	if uid == "" {
		return "", "", false
	}
	var q string
	args := []any{}
	if len(uid) == 36 { // full UUID → 정확 매칭
		q = `SELECT name, COALESCE(namespace,'') FROM pod_master WHERE pod_uid = $1`
		args = append(args, uid)
	} else { // short prefix (예: 8b4f732c) → 접두 매칭
		q = `SELECT name, COALESCE(namespace,'') FROM pod_master WHERE pod_uid LIKE $1`
		args = append(args, uid+"%")
	}
	if clusterName != "" {
		q += fmt.Sprintf(" AND cluster_name = $%d", len(args)+1)
		args = append(args, clusterName)
	}
	q += " AND deleted_at IS NULL ORDER BY last_seen_at DESC LIMIT 1"

	if err := r.pg.QueryRow(ctx, q, args...).Scan(&name, &namespace); err != nil {
		return "", "", false
	}
	return name, namespace, true
}

// PodMasterRow holds lifecycle metadata from the pod_master table.
type PodMasterRow struct {
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// GetPodMasterByName returns lifecycle timestamps from pod_master.
func (r *ClusterReaderRepo) GetPodMasterByName(ctx context.Context, clusterName, podUID string) (*PodMasterRow, error) {
	var m PodMasterRow
	err := r.pg.QueryRow(ctx,
		`SELECT first_seen_at, last_seen_at FROM pod_master
		  WHERE cluster_name = $1 AND pod_uid = $2 AND deleted_at IS NULL`,
		clusterName, podUID,
	).Scan(&m.FirstSeenAt, &m.LastSeenAt)
	if err != nil {
		return nil, fmt.Errorf("get pod master: %w", err)
	}
	return &m, nil
}

// ClusterRelatedRows holds related K8s resources from DB for assembling PodGraphRequest.
type ClusterRelatedRows struct {
	Services             []map[string]any
	Ingresses            []map[string]any
	NetworkPolicies      []map[string]any
	Workloads            []map[string]any
	Nodes                []map[string]any
	ClusterRoles         []map[string]any
	ClusterRoleBindings  []map[string]any
	Roles                []map[string]any
	RoleBindings         []map[string]any
	ServiceAccounts      []map[string]any
	Secrets              []map[string]any
	ConfigMaps           []map[string]any
	Namespaces           []string
	NamespacesInCluster  []map[string]any // Full namespace objects with metadata (for finding evaluator)
	EBPFProcessEvents    []map[string]any
	ImageVulnerabilities []map[string]any
	SecurityGroups       []map[string]any // AWS Security Groups (account/region-global, 최신 SG 스냅샷)
	CloudTrailTrails     []map[string]any // AWS CloudTrail trails (account/region-global, 최신 스냅샷)
	KmsKeys              []map[string]any // AWS KMS keys (account/region-global, 최신 스냅샷)
	EKSAuthenticationMode string          // EKS access config: authentication_mode (API|CONFIG_MAP|API_AND_CONFIG_MAP), "" if 미수집
}

// GetRelatedResources loads all related K8s resources for a cluster/snapshot/namespace.
func (r *ClusterReaderRepo) GetRelatedResources(
	ctx context.Context,
	clusterName string,
	snapshotAt time.Time,
	namespace string,
) (*ClusterRelatedRows, error) {
	res := &ClusterRelatedRows{}

	// ── Services (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, type, cluster_ip, external_name, selector, ports
			 FROM cluster_services
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_services
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query services: %w", err)
		}
		res.Services, err = scanServicesRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Ingresses (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, ingress_class, rules, tls, annotations
			 FROM cluster_ingresses
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_ingresses
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query ingresses: %w", err)
		}
		res.Ingresses, err = scanIngressRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── NetworkPolicies (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, pod_selector, policy_types, ingress_rules, egress_rules
			 FROM cluster_network_policies
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_network_policies
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query network_policies: %w", err)
		}
		res.NetworkPolicies, err = scanNetworkPolicyRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Workloads (namespace-scoped, nearest snapshot) ──
	// 수집기가 Pod과 Workload를 별도 주기로 적재하므로 snapshot_at이 수십 초 어긋남.
	// exact match 대신 가장 가까운 snapshot을 사용.
	{
		rows, err := r.pg.Query(ctx,
			`SELECT kind, name, namespace, selector, template_labels, containers
			 FROM cluster_workloads
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_workloads
			       WHERE cluster_name=$1 AND namespace=$3
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query workloads: %w", err)
		}
		res.Workloads, err = scanWorkloadRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Roles (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, rules FROM cluster_roles
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_roles
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query roles: %w", err)
		}
		res.Roles, err = scanRoleRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── RoleBindings (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, role_ref, subjects FROM cluster_role_bindings
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_role_bindings
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query role_bindings: %w", err)
		}
		res.RoleBindings, err = scanBindingRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ServiceAccounts (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, secrets FROM cluster_service_accounts
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_service_accounts
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query service_accounts: %w", err)
		}
		res.ServiceAccounts, err = scanServiceAccountRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Secrets (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, type FROM cluster_secrets
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_secrets
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query secrets: %w", err)
		}
		res.Secrets, err = scanSecretRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ConfigMaps (namespace-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace FROM cluster_configmaps
			 WHERE cluster_name=$1 AND namespace=$3
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_configmaps
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt, namespace)
		if err != nil {
			return nil, fmt.Errorf("query configmaps: %w", err)
		}
		res.ConfigMaps, err = scanConfigMapRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Nodes (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, kubelet_version FROM cluster_nodes
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_nodes
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query nodes: %w", err)
		}
		res.Nodes, err = scanNodeRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ClusterRoles (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, rules FROM cluster_cluster_roles
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_cluster_roles
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query cluster_roles: %w", err)
		}
		res.ClusterRoles, err = scanClusterRoleRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ClusterRoleBindings (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, role_ref, subjects FROM cluster_cluster_role_bindings
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_cluster_role_bindings
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query cluster_role_bindings: %w", err)
		}
		res.ClusterRoleBindings, err = scanClusterBindingRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Namespaces (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT namespace FROM cluster_namespaces
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_namespaces
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query namespaces: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var ns string
			if err := rows.Scan(&ns); err != nil {
				return nil, fmt.Errorf("scan namespace: %w", err)
			}
			res.Namespaces = append(res.Namespaces, ns)
		}
	}

	// ── eBPF Process Events (namespace-scoped, best-effort) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT src_pod_id, comm, timestamp
			 FROM ebpf_process_events
			 WHERE cluster_name=$1 AND src_pod_id LIKE $2 || '/%'
			 ORDER BY timestamp DESC LIMIT 100`,
			clusterName, namespace)
		if err == nil {
			if events, scanErr := scanEBPFProcessRows(rows); scanErr != nil {
				log.Printf("warn: scan ebpf_process_events (namespace-scoped): %v", scanErr)
			} else {
				res.EBPFProcessEvents = events
			}
		} else {
			// Best-effort: table may be absent or have a different schema.
			// Log a warning so the next schema mismatch is not silently hidden.
			log.Printf("warn: query ebpf_process_events (namespace-scoped): %v", err)
		}
	}

	return res, nil
}

// GetClusterWideResources loads ALL K8s resources for a cluster (no namespace filter).
// Used by the Finding evaluator for cluster-wide analysis.
func (r *ClusterReaderRepo) GetClusterWideResources(
	ctx context.Context,
	clusterName string,
	snapshotAt time.Time,
) (*ClusterRelatedRows, error) {
	res := &ClusterRelatedRows{}

	// ── Services (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, type, cluster_ip, external_name, selector, ports
			 FROM cluster_services
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_services
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query services: %w", err)
		}
		res.Services, err = scanServicesRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Ingresses (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, ingress_class, rules, tls, annotations
			 FROM cluster_ingresses
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_ingresses
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query ingresses: %w", err)
		}
		res.Ingresses, err = scanIngressRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── NetworkPolicies (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, pod_selector, policy_types, ingress_rules, egress_rules
			 FROM cluster_network_policies
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_network_policies
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query network_policies: %w", err)
		}
		res.NetworkPolicies, err = scanNetworkPolicyRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── AWS Security Groups (account/region-global; 최신 SG 스냅샷) ──
	// SG는 cluster_name이 아니라 account/region 키라 클러스터 스냅샷과 별개로
	// 가장 최근 SG 스냅샷을 적재한다. (단일 계정 가정; 다계정이면 account_id 필터 추가)
	{
		rows, err := r.pg.Query(ctx,
			`SELECT group_id, group_name, vpc_id, description, ingress_rules, egress_rules
			 FROM aws_security_groups
			 WHERE snapshot_at = (SELECT MAX(snapshot_at) FROM aws_security_groups)`)
		if err != nil {
			return nil, fmt.Errorf("query security_groups: %w", err)
		}
		res.SecurityGroups, err = scanSecurityGroupRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── AWS CloudTrail trails (account/region-global; 최신 스냅샷) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, trail_arn, home_region, s3_bucket, is_multi_region,
			        include_global_events, kms_key_id, log_file_validation_enabled, is_logging
			 FROM aws_cloudtrail_trails
			 WHERE snapshot_at = (SELECT MAX(snapshot_at) FROM aws_cloudtrail_trails)`)
		if err != nil {
			return nil, fmt.Errorf("query cloudtrail_trails: %w", err)
		}
		res.CloudTrailTrails, err = scanCloudTrailRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── AWS KMS keys (account/region-global; 최신 스냅샷) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT key_id, arn, key_state, key_manager, key_spec, enabled, rotation_enabled
			 FROM aws_kms_keys
			 WHERE snapshot_at = (SELECT MAX(snapshot_at) FROM aws_kms_keys)`)
		if err != nil {
			return nil, fmt.Errorf("query kms_keys: %w", err)
		}
		res.KmsKeys, err = scanKmsKeyRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── EKS access config (authentication_mode) — CIS 4.1.7 / R-2.5.5-07 ──
	{
		var mode *string
		if err := r.pg.QueryRow(ctx,
			`SELECT authentication_mode FROM cluster_aws_config
			 WHERE cluster_name=$1
			 ORDER BY snapshot_at DESC LIMIT 1`,
			clusterName).Scan(&mode); err == nil && mode != nil {
			res.EKSAuthenticationMode = *mode
		}
		// no rows / IAM 권한 없음 → "" 유지 → 룰이 NO_DATA 처리
	}

	// ── Workloads (all namespaces, nearest snapshot) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT kind, name, namespace, selector, template_labels, containers
			 FROM cluster_workloads
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_workloads
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query workloads: %w", err)
		}
		res.Workloads, err = scanWorkloadRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Roles (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, rules FROM cluster_roles
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_roles
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query roles: %w", err)
		}
		res.Roles, err = scanRoleRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── RoleBindings (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, role_ref, subjects FROM cluster_role_bindings
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_role_bindings
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query role_bindings: %w", err)
		}
		res.RoleBindings, err = scanBindingRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ServiceAccounts (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, secrets FROM cluster_service_accounts
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_service_accounts
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query service_accounts: %w", err)
		}
		res.ServiceAccounts, err = scanServiceAccountRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Secrets (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace, type FROM cluster_secrets
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_secrets
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query secrets: %w", err)
		}
		res.Secrets, err = scanSecretRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ConfigMaps (all namespaces) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, namespace FROM cluster_configmaps
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_configmaps
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query configmaps: %w", err)
		}
		res.ConfigMaps, err = scanConfigMapRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Nodes (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, kubelet_version FROM cluster_nodes
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_nodes
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query nodes: %w", err)
		}
		res.Nodes, err = scanNodeRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ClusterRoles (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, rules FROM cluster_cluster_roles
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_cluster_roles
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query cluster_roles: %w", err)
		}
		res.ClusterRoles, err = scanClusterRoleRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── ClusterRoleBindings (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT name, role_ref, subjects FROM cluster_cluster_role_bindings
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_cluster_role_bindings
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query cluster_role_bindings: %w", err)
		}
		res.ClusterRoleBindings, err = scanClusterBindingRows(rows)
		if err != nil {
			return nil, err
		}
	}

	// ── Namespaces (cluster-scoped) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT namespace FROM cluster_namespaces
			 WHERE cluster_name=$1
			   AND snapshot_at = (
			       SELECT snapshot_at FROM cluster_namespaces
			       WHERE cluster_name=$1
			       ORDER BY ABS(EXTRACT(EPOCH FROM snapshot_at - $2::timestamptz)) LIMIT 1
			   )`,
			clusterName, snapshotAt)
		if err != nil {
			return nil, fmt.Errorf("query namespaces: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var ns string
			if err := rows.Scan(&ns); err != nil {
				return nil, fmt.Errorf("scan namespace: %w", err)
			}
			res.Namespaces = append(res.Namespaces, ns)
			// Build NamespacesInCluster with metadata for finding evaluator
			res.NamespacesInCluster = append(res.NamespacesInCluster, map[string]any{
				"metadata": map[string]any{
					"name":   ns,
					"labels": map[string]any{}, // No labels in DB schema; evaluator handles gracefully
				},
			})
		}
	}

	// ── eBPF Process Events (all namespaces, best-effort) ──
	{
		rows, err := r.pg.Query(ctx,
			`SELECT src_pod_id, comm, timestamp
			 FROM ebpf_process_events
			 WHERE cluster_name=$1
			 ORDER BY timestamp DESC LIMIT 500`,
			clusterName)
		if err == nil {
			if events, scanErr := scanEBPFProcessRows(rows); scanErr != nil {
				log.Printf("warn: scan ebpf_process_events (cluster-wide): %v", scanErr)
			} else {
				res.EBPFProcessEvents = events
			}
		} else {
			log.Printf("warn: query ebpf_process_events (cluster-wide): %v", err)
		}
	}

	return res, nil
}

// ── Row scanners ──

func scanServicesRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns, svcType string
		var clusterIP, externalName *string
		var selector, ports json.RawMessage
		if err := rows.Scan(&name, &ns, &svcType, &clusterIP, &externalName, &selector, &ports); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}
		spec := map[string]any{"type": svcType}
		if clusterIP != nil {
			spec["clusterIP"] = *clusterIP
		}
		if externalName != nil {
			spec["externalName"] = *externalName
		}
		var sel map[string]any
		_ = json.Unmarshal(selector, &sel)
		if sel != nil {
			spec["selector"] = sel
		}
		var p []any
		_ = json.Unmarshal(ports, &p)
		if p != nil {
			spec["ports"] = p
		}
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec":     spec,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanIngressRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		var ingressClass *string
		var rules, tls, annRaw json.RawMessage
		if err := rows.Scan(&name, &ns, &ingressClass, &rules, &tls, &annRaw); err != nil {
			return nil, fmt.Errorf("scan ingress: %w", err)
		}
		annotations := map[string]any{}
		annotationsCollected := false
		if annRaw != nil {
			annotationsCollected = true
			var am map[string]any
			if json.Unmarshal(annRaw, &am) == nil {
				for k, v := range am {
					annotations[k] = v
				}
			}
		}
		if ingressClass != nil {
			annotations["kubernetes.io/ingress.class"] = *ingressClass
		}
		spec := map[string]any{}
		var r []any
		_ = json.Unmarshal(rules, &r)
		if r != nil {
			spec["rules"] = r
		}
		var t []any
		_ = json.Unmarshal(tls, &t)
		if t != nil {
			spec["tls"] = t
		}
		m := map[string]any{
			"metadata":               map[string]any{"name": name, "namespace": ns, "annotations": annotations},
			"spec":                   spec,
			"_annotations_collected": annotationsCollected,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanNetworkPolicyRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		var podSelector, policyTypes, ingressRules, egressRules json.RawMessage
		if err := rows.Scan(&name, &ns, &podSelector, &policyTypes, &ingressRules, &egressRules); err != nil {
			return nil, fmt.Errorf("scan network_policy: %w", err)
		}
		spec := map[string]any{}
		var ps map[string]any
		_ = json.Unmarshal(podSelector, &ps)
		spec["podSelector"] = ps
		var pt []any
		_ = json.Unmarshal(policyTypes, &pt)
		spec["policyTypes"] = pt
		var ir []any
		_ = json.Unmarshal(ingressRules, &ir)
		spec["ingress"] = ir
		var er []any
		_ = json.Unmarshal(egressRules, &er)
		spec["egress"] = er
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
			"spec":     spec,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanSecurityGroupRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	var result []map[string]any
	for rows.Next() {
		var groupID string
		var groupName, vpcID, description *string
		var ingressRules, egressRules json.RawMessage
		if err := rows.Scan(&groupID, &groupName, &vpcID, &description, &ingressRules, &egressRules); err != nil {
			return nil, fmt.Errorf("scan security_group: %w", err)
		}
		var ir, er []any
		_ = json.Unmarshal(ingressRules, &ir)
		_ = json.Unmarshal(egressRules, &er)
		result = append(result, map[string]any{
			"group_id":      groupID,
			"group_name":    deref(groupName),
			"vpc_id":        deref(vpcID),
			"description":   deref(description),
			"ingress_rules": ir,
			"egress_rules":  er,
		})
	}
	return result, nil
}

func scanCloudTrailRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	derefB := func(p *bool) bool {
		if p == nil {
			return false
		}
		return *p
	}
	var result []map[string]any
	for rows.Next() {
		var name, trailArn string
		var homeRegion, s3Bucket, kmsKeyID *string
		var isMultiRegion, includeGlobal, logValidation, isLogging *bool
		if err := rows.Scan(&name, &trailArn, &homeRegion, &s3Bucket, &isMultiRegion,
			&includeGlobal, &kmsKeyID, &logValidation, &isLogging); err != nil {
			return nil, fmt.Errorf("scan cloudtrail: %w", err)
		}
		result = append(result, map[string]any{
			"name":                        name,
			"trail_arn":                   trailArn,
			"home_region":                 deref(homeRegion),
			"s3_bucket":                   deref(s3Bucket),
			"is_multi_region":             derefB(isMultiRegion),
			"include_global_events":       derefB(includeGlobal),
			"kms_key_id":                  deref(kmsKeyID),
			"log_file_validation_enabled": derefB(logValidation),
			"is_logging":                  derefB(isLogging),
		})
	}
	return result, nil
}

func scanKmsKeyRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	derefB := func(p *bool) bool {
		if p == nil {
			return false
		}
		return *p
	}
	var result []map[string]any
	for rows.Next() {
		var keyID, arn string
		var keyState, keyManager, keySpec *string
		var enabled, rotationEnabled *bool
		if err := rows.Scan(&keyID, &arn, &keyState, &keyManager, &keySpec, &enabled, &rotationEnabled); err != nil {
			return nil, fmt.Errorf("scan kms key: %w", err)
		}
		result = append(result, map[string]any{
			"key_id":           keyID,
			"arn":              arn,
			"key_state":        deref(keyState),
			"key_manager":      deref(keyManager),
			"key_spec":         deref(keySpec),
			"enabled":          derefB(enabled),
			"rotation_enabled": derefB(rotationEnabled),
		})
	}
	return result, nil
}

func scanWorkloadRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var kind, name, ns string
		var selector, templateLabels, containers json.RawMessage
		if err := rows.Scan(&kind, &name, &ns, &selector, &templateLabels, &containers); err != nil {
			return nil, fmt.Errorf("scan workload: %w", err)
		}
		annotations := map[string]any{}
		spec := map[string]any{}
		var sel map[string]any
		_ = json.Unmarshal(selector, &sel)
		if sel != nil {
			spec["selector"] = sel
		}
		var tmplLabels map[string]any
		_ = json.Unmarshal(templateLabels, &tmplLabels)
		if tmplLabels == nil {
			tmplLabels = map[string]any{}
		}
		spec["template"] = map[string]any{
			"metadata": map[string]any{
				"labels": tmplLabels,
			},
		}
		m := map[string]any{
			"kind":     kind,
			"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{}, "annotations": annotations},
			"spec":     spec,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanNodeRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name string
		var kubeletVersion *string
		if err := rows.Scan(&name, &kubeletVersion); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		nodeInfo := map[string]any{}
		if kubeletVersion != nil {
			nodeInfo["kubeletVersion"] = *kubeletVersion
		}
		m := map[string]any{
			"metadata": map[string]any{"name": name},
			"status":   map[string]any{"nodeInfo": nodeInfo},
		}
		result = append(result, m)
	}
	return result, nil
}

func scanRoleRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		var rules json.RawMessage
		if err := rows.Scan(&name, &ns, &rules); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		var r []any
		_ = json.Unmarshal(rules, &r)
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
			"rules":    r,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanClusterRoleRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name string
		var rules json.RawMessage
		if err := rows.Scan(&name, &rules); err != nil {
			return nil, fmt.Errorf("scan cluster_role: %w", err)
		}
		var r []any
		_ = json.Unmarshal(rules, &r)
		m := map[string]any{
			"metadata": map[string]any{"name": name},
			"rules":    r,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanBindingRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		var roleRef, subjects json.RawMessage
		if err := rows.Scan(&name, &ns, &roleRef, &subjects); err != nil {
			return nil, fmt.Errorf("scan role_binding: %w", err)
		}
		var ref map[string]any
		_ = json.Unmarshal(roleRef, &ref)
		var subj []any
		_ = json.Unmarshal(subjects, &subj)
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
			"roleRef":  ref,
			"subjects": subj,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanClusterBindingRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name string
		var roleRef, subjects json.RawMessage
		if err := rows.Scan(&name, &roleRef, &subjects); err != nil {
			return nil, fmt.Errorf("scan cluster_role_binding: %w", err)
		}
		var ref map[string]any
		_ = json.Unmarshal(roleRef, &ref)
		var subj []any
		_ = json.Unmarshal(subjects, &subj)
		m := map[string]any{
			"metadata": map[string]any{"name": name},
			"roleRef":  ref,
			"subjects": subj,
		}
		result = append(result, m)
	}
	return result, nil
}

func scanServiceAccountRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		var secrets json.RawMessage
		if err := rows.Scan(&name, &ns, &secrets); err != nil {
			return nil, fmt.Errorf("scan service_account: %w", err)
		}
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns, "labels": map[string]any{}},
		}
		result = append(result, m)
	}
	return result, nil
}

func scanSecretRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		var secretType *string
		if err := rows.Scan(&name, &ns, &secretType); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
		}
		if secretType != nil {
			m["type"] = *secretType
		}
		result = append(result, m)
	}
	return result, nil
}

func scanEBPFProcessRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var srcPodID *string
		var comm string
		var ts time.Time
		if err := rows.Scan(&srcPodID, &comm, &ts); err != nil {
			return nil, fmt.Errorf("scan ebpf_process: %w", err)
		}
		// src_pod_id = "namespace/name" (호스트 프로세스면 빈 문자열/NULL)
		sp := ""
		if srcPodID != nil {
			sp = *srcPodID
		}
		ns, podName := "", ""
		for i := 0; i < len(sp); i++ {
			if sp[i] == '/' {
				ns, podName = sp[:i], sp[i+1:]
				break
			}
		}
		m := map[string]any{
			"pod_name":    podName,
			"namespace":   ns,
			"process":     comm,
			"binary":      comm,
			"binary_path": comm,
			"timestamp":   ts.Format(time.RFC3339),
		}
		result = append(result, m)
	}
	return result, nil
}

func scanConfigMapRows(rows pgx.Rows) ([]map[string]any, error) {
	defer rows.Close()
	var result []map[string]any
	for rows.Next() {
		var name, ns string
		if err := rows.Scan(&name, &ns); err != nil {
			return nil, fmt.Errorf("scan configmap: %w", err)
		}
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns},
		}
		result = append(result, m)
	}
	return result, nil
}
