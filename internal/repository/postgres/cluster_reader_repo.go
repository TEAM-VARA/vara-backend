package postgres

import (
	"context"
	"encoding/json"
	"fmt"

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
			host_network, started_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
		ON CONFLICT (cluster_name, snapshot_at, pod_uid) DO UPDATE SET
			phase             = EXCLUDED.phase,
			restart_count     = EXCLUDED.restart_count,
			pod_ip            = EXCLUDED.pod_ip,
			containers        = EXCLUDED.containers,
			volumes           = EXCLUDED.volumes,
			host_network      = EXCLUDED.host_network,
			started_at        = EXCLUDED.started_at
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
			p.HostNetwork, p.StartedAt,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("upsert pod %s: %w", p.Name, err)
		}
		saved++
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
			ingress_class, rules, tls
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
		ON CONFLICT (cluster_name, snapshot_at, ingress_uid) DO UPDATE SET
			ingress_class = EXCLUDED.ingress_class,
			rules         = EXCLUDED.rules,
			tls           = EXCLUDED.tls
	`

	saved := 0
	for _, ing := range req.Ingresses {
		rulesJSON, _ := json.Marshal(ing.Rules)
		tlsJSON, _ := json.Marshal(ing.TLS)

		_, err := tx.Exec(ctx, q,
			req.Cluster, req.SnapshotAt, ing.UID, ing.Name, ing.Namespace,
			ing.IngressClass, rulesJSON, tlsJSON,
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
			cluster_name, snapshot_at, sa_uid, name, namespace, secrets
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (cluster_name, snapshot_at, sa_uid) DO UPDATE SET
			secrets = EXCLUDED.secrets
	`
	for _, sa := range req.ServiceAccounts {
		secrets := sa.Secrets
		if secrets == nil {
			secrets = []string{}
		}
		secretsJSON, _ := json.Marshal(secrets)
		_, err := tx.Exec(ctx, saQ,
			req.Cluster, req.SnapshotAt, sa.UID, sa.Name, sa.Namespace, secretsJSON)
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
