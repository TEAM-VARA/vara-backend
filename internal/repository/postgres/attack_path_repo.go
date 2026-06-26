package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/scoring"
)

// AttackPathRepo는 공격 경로 범위 평가에 필요한 데이터를 조회하고,
// 계산 결과를 attack_path_scores 테이블에 저장합니다.
//
// 조회 데이터 (각 테이블의 최신 snapshot):
//   - cluster_pods                      (serviceAccount, labels, containers, volumes)
//   - cluster_cluster_role_bindings     (SA → ClusterRole)
//   - cluster_role_bindings             (SA → Role, namespace)
//   - cluster_cluster_roles             (rules)
//   - cluster_roles                     (rules, namespace)
//   - cluster_network_policies          (podSelector, policyTypes)
//
// 시점 정책: 각 테이블의 MAX(snapshot_at)을 독립적으로 조회
// (작업 C-1과 동일 — 각 collector의 snapshot_at은 독립)
type AttackPathRepo struct {
	pool *pgxpool.Pool
}

// NewAttackPathRepo는 AttackPathRepo를 생성합니다.
func NewAttackPathRepo(pool *pgxpool.Pool) *AttackPathRepo {
	return &AttackPathRepo{pool: pool}
}

// LatestSnapshotAt: 이 클러스터의 최신 배치 snapshot_at. 행 없으면 ok=false(폴백).
func (r *AttackPathRepo) LatestSnapshotAt(ctx context.Context, cluster string) (time.Time, bool, error) {
	var t *time.Time
	if err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM attack_path_scores WHERE cluster_name=$1`, cluster).Scan(&t); err != nil {
		return time.Time{}, false, fmt.Errorf("latest snapshot: %w", err)
	}
	if t == nil {
		return time.Time{}, false, nil
	}
	return *t, true, nil
}

// ─────────────────────────────────────────
// 조회용 DTO
// ─────────────────────────────────────────

// PodForAttackPath는 공격 경로 평가에 필요한 Pod 정보입니다.
type PodForAttackPath struct {
	PodUID         string
	Name           string
	Namespace      string
	ServiceAccount string
	PodIP          string
	Labels         map[string]string
	Containers     []ContainerInfo // 컨테이너의 securityContext
	HostNetwork    bool
	HostPID        bool
	HostIPC        bool
	Volumes        []VolumeInfo
}

// ContainerInfo는 보안 컨텍스트 평가에 필요한 컨테이너 정보입니다.
type ContainerInfo struct {
	Name       string
	Privileged bool
}

// VolumeInfo는 마운트 타입 평가에 필요한 볼륨 정보입니다.
type VolumeInfo struct {
	Name string
	Type string // "hostPath" | "secret" | "configMap" | "other"
}

// RoleBindingMatch는 Pod의 SA에 매핑된 RoleBinding/ClusterRoleBinding 정보입니다.
type RoleBindingMatch struct {
	BindingName  string // RoleBinding/ClusterRoleBinding 이름
	BindingScope string // "namespace" | "cluster"
	RoleName     string
	RoleScope    string // "namespace" | "cluster"
	RoleRules    []RoleRule
}

// RoleRule은 Role/ClusterRole의 rule 한 건입니다.
type RoleRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// NetworkPolicyMatch는 Pod에 매핑된 NetworkPolicy 정보입니다.
type NetworkPolicyMatch struct {
	Name        string
	Namespace   string
	PolicyTypes []string // ["Ingress"], ["Egress"], ["Ingress", "Egress"]
}

// ─────────────────────────────────────────
// 각 테이블의 최신 snapshot_at 조회
// ─────────────────────────────────────────

// GetLatestPodsSnapshot은 cluster_pods의 최신 snapshot_at을 반환합니다.
func (r *AttackPathRepo) GetLatestPodsSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	return r.getLatestSnapshot(ctx, "cluster_pods", clusterName, true)
}

func (r *AttackPathRepo) GetLatestClusterRoleBindingsSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	return r.getLatestSnapshot(ctx, "cluster_cluster_role_bindings", clusterName, false)
}

func (r *AttackPathRepo) GetLatestRoleBindingsSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	return r.getLatestSnapshot(ctx, "cluster_role_bindings", clusterName, false)
}

func (r *AttackPathRepo) GetLatestClusterRolesSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	return r.getLatestSnapshot(ctx, "cluster_cluster_roles", clusterName, false)
}

func (r *AttackPathRepo) GetLatestRolesSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	return r.getLatestSnapshot(ctx, "cluster_roles", clusterName, false)
}

func (r *AttackPathRepo) GetLatestNetworkPoliciesSnapshot(ctx context.Context, clusterName string) (time.Time, error) {
	return r.getLatestSnapshot(ctx, "cluster_network_policies", clusterName, false)
}

// getLatestSnapshot은 공통 헬퍼. required=true면 데이터 없을 때 에러,
// false면 zero time 반환 (옵셔널 테이블용).
func (r *AttackPathRepo) getLatestSnapshot(ctx context.Context, tableName, clusterName string, required bool) (time.Time, error) {
	var t *time.Time
	query := fmt.Sprintf(`SELECT MAX(snapshot_at) FROM %s WHERE cluster_name = $1`, tableName)
	err := r.pool.QueryRow(ctx, query, clusterName).Scan(&t)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, fmt.Errorf("get latest snapshot %s: %w", tableName, err)
	}
	if t == nil {
		if required {
			return time.Time{}, fmt.Errorf("no data in %s for cluster %s", tableName, clusterName)
		}
		return time.Time{}, nil
	}
	return *t, nil
}

// ─────────────────────────────────────────
// Pod 데이터 조회
// ─────────────────────────────────────────

// ListPodsForAttackPath는 특정 snapshot의 Pod 정보를 attack-path 평가용으로 반환합니다.
//
// cluster_pods JSONB 구조:
//   - containers: [{"name": "...", "securityContext": {"privileged": true}, ...}]
//   - volumes:    [{"name": "...", "hostPath": {...}}, {"name": "...", "secret": {...}}, ...]
//
// containers 안에 hostNetwork 같은 Pod 레벨 spec은 들어있지 않을 수 있음.
// cluster_pods 테이블 자체에 hostNetwork 컬럼이 없으면 containers JSONB에서 추출 시도.
func (r *AttackPathRepo) ListPodsForAttackPath(ctx context.Context, clusterName string, snapshotAt time.Time) ([]PodForAttackPath, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT
			pod_uid, name, namespace,
			COALESCE(pod_ip, '') AS pod_ip,
			COALESCE(service_account, '') AS service_account,
			COALESCE(labels, '{}'::jsonb) AS labels,
			COALESCE(containers, '[]'::jsonb) AS containers,
			COALESCE(volumes, '[]'::jsonb) AS volumes
		 FROM cluster_pods
		 WHERE cluster_name = $1 AND snapshot_at = $2`,
		clusterName, snapshotAt,
	)
	if err != nil {
		return nil, fmt.Errorf("query pods for attack-path: %w", err)
	}
	defer rows.Close()

	var out []PodForAttackPath
	for rows.Next() {
		var p PodForAttackPath
		var labelsRaw, containersRaw, volumesRaw []byte
		if err := rows.Scan(&p.PodUID, &p.Name, &p.Namespace, &p.PodIP, &p.ServiceAccount,
			&labelsRaw, &containersRaw, &volumesRaw); err != nil {
			return nil, fmt.Errorf("scan pod: %w", err)
		}

		// Labels
		if len(labelsRaw) > 0 {
			_ = json.Unmarshal(labelsRaw, &p.Labels)
		}
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}

		// Containers (특히 securityContext.privileged)
		p.Containers = parseContainers(containersRaw)

		// Volumes (hostPath, secret, configMap 식별)
		p.Volumes = parseVolumes(volumesRaw)

		// hostNetwork/hostPID/hostIPC는 cluster_pods의 별도 컬럼이 없으면 false 처리
		// 우회: service 레이어에서 cluster_nodes.internal_ip와 PodIP 비교로 추론
		// 추후 cluster-reader가 host_network 컬럼을 따로 노출하면 여기서 채움

		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPodForAttackPathByUID는 특정 snapshot의 단일 Pod를 attack-path 분석용으로 반환합니다.
// snapshot이 zero time이거나 Pod가 없으면 nil 반환.
func (r *AttackPathRepo) GetPodForAttackPathByUID(
	ctx context.Context,
	clusterName string,
	snapshotAt time.Time,
	podUID string,
) (*PodForAttackPath, error) {
	if snapshotAt.IsZero() {
		return nil, nil
	}

	var p PodForAttackPath
	var labelsRaw, containersRaw, volumesRaw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT
			pod_uid, name, namespace,
			COALESCE(pod_ip, '') AS pod_ip,
			COALESCE(service_account, '') AS service_account,
			COALESCE(labels, '{}'::jsonb) AS labels,
			COALESCE(containers, '[]'::jsonb) AS containers,
			COALESCE(volumes, '[]'::jsonb) AS volumes
		 FROM cluster_pods
		 WHERE cluster_name = $1 AND snapshot_at = $2 AND pod_uid = $3`,
		clusterName, snapshotAt, podUID,
	).Scan(&p.PodUID, &p.Name, &p.Namespace, &p.PodIP, &p.ServiceAccount,
		&labelsRaw, &containersRaw, &volumesRaw)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query pod for attack-path by uid: %w", err)
	}

	if len(labelsRaw) > 0 {
		_ = json.Unmarshal(labelsRaw, &p.Labels)
	}
	if p.Labels == nil {
		p.Labels = map[string]string{}
	}
	p.Containers = parseContainers(containersRaw)
	p.Volumes = parseVolumes(volumesRaw)

	return &p, nil
}

// parseContainers는 cluster_pods.containers JSONB를 ContainerInfo 슬라이스로 변환.
//
// 예상 구조:
//
//	[{"name": "nginx", "image": "...", "securityContext": {"privileged": false}, ...}]
//
// 참고: cluster-reader agent 구현에 따라 securityContext 필드 형태가 다를 수 있음.
// 가능한 변형 모두 대응.
func parseContainers(raw []byte) []ContainerInfo {
	if len(raw) == 0 {
		return nil
	}

	var rawContainers []map[string]interface{}
	if err := json.Unmarshal(raw, &rawContainers); err != nil {
		return nil
	}

	out := make([]ContainerInfo, 0, len(rawContainers))
	for _, c := range rawContainers {
		ci := ContainerInfo{}
		if name, ok := c["name"].(string); ok {
			ci.Name = name
		}
		// securityContext.privileged 확인
		if sc, ok := c["securityContext"].(map[string]interface{}); ok {
			if priv, ok := sc["privileged"].(bool); ok {
				ci.Privileged = priv
			}
		}
		// 다른 가능한 위치: privileged 단독 필드
		if priv, ok := c["privileged"].(bool); ok {
			ci.Privileged = priv
		}
		out = append(out, ci)
	}
	return out
}

// parseVolumes는 cluster_pods.volumes JSONB에서 마운트 타입을 식별합니다.
//
// 예상 구조:
//
//	[{"name": "data", "hostPath": {...}}, {"name": "secret-vol", "secret": {...}}, ...]
func parseVolumes(raw []byte) []VolumeInfo {
	if len(raw) == 0 {
		return nil
	}

	var rawVolumes []map[string]interface{}
	if err := json.Unmarshal(raw, &rawVolumes); err != nil {
		return nil
	}

	out := make([]VolumeInfo, 0, len(rawVolumes))
	for _, v := range rawVolumes {
		vi := VolumeInfo{Type: "other"}
		if name, ok := v["name"].(string); ok {
			vi.Name = name
		}

		// 가능한 타입 키들 확인 (K8s spec)
		if _, ok := v["hostPath"]; ok {
			vi.Type = "hostPath"
		} else if _, ok := v["secret"]; ok {
			vi.Type = "secret"
		} else if _, ok := v["configMap"]; ok {
			vi.Type = "configMap"
		}

		// 별도 type 필드도 확인 (cluster-reader가 평탄화한 경우)
		if t, ok := v["type"].(string); ok && t != "" {
			vi.Type = t
		}

		out = append(out, vi)
	}
	return out
}

// ─────────────────────────────────────────
// RBAC 데이터 조회
// ─────────────────────────────────────────

// ListClusterRoleBindingsForSA는 ServiceAccount(namespace, name)에 매핑된
// ClusterRoleBinding을 찾고, 연결된 ClusterRole의 rules를 함께 반환합니다.
//
// 매핑 로직:
//
//	ClusterRoleBinding.subjects[].kind == "ServiceAccount"
//	AND ClusterRoleBinding.subjects[].name == saName
//	AND ClusterRoleBinding.subjects[].namespace == saNamespace
//
// 결과: 매핑된 ClusterRoleBinding과 그 ClusterRole의 rules
func (r *AttackPathRepo) ListClusterRoleBindingsForSA(
	ctx context.Context,
	clusterName, saNamespace, saName string,
	crbSnapshot, crSnapshot time.Time,
) ([]RoleBindingMatch, error) {

	if crbSnapshot.IsZero() {
		return nil, nil
	}

	// 1. 해당 SA를 subject로 가진 ClusterRoleBinding 찾기
	query := `
		SELECT 
			crb.name AS binding_name,
			crb.role_ref->>'name' AS role_name,
			crb.role_ref->>'kind' AS role_kind
		FROM cluster_cluster_role_bindings crb,
		     jsonb_array_elements(crb.subjects) AS subj
		WHERE crb.cluster_name = $1
		  AND crb.snapshot_at = $2
		  AND subj->>'kind' = 'ServiceAccount'
		  AND subj->>'name' = $3
		  AND COALESCE(subj->>'namespace', '') = $4
	`
	rows, err := r.pool.Query(ctx, query, clusterName, crbSnapshot, saName, saNamespace)
	if err != nil {
		return nil, fmt.Errorf("query crb for SA: %w", err)
	}
	defer rows.Close()

	type bindingRef struct {
		BindingName string
		RoleName    string
		RoleKind    string
	}
	var bindings []bindingRef
	for rows.Next() {
		var b bindingRef
		if err := rows.Scan(&b.BindingName, &b.RoleName, &b.RoleKind); err != nil {
			return nil, fmt.Errorf("scan crb: %w", err)
		}
		bindings = append(bindings, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 2. 각 binding에 대해 ClusterRole rules 조회
	var out []RoleBindingMatch
	for _, b := range bindings {
		match := RoleBindingMatch{
			BindingName:  b.BindingName,
			BindingScope: "cluster",
			RoleName:     b.RoleName,
			RoleScope:    "cluster",
		}

		// ClusterRole 조회
		if !crSnapshot.IsZero() && b.RoleKind == "ClusterRole" {
			rules, err := r.getClusterRoleRules(ctx, clusterName, b.RoleName, crSnapshot)
			if err != nil {
				// 못 찾으면 빈 rules로 진행 (그 binding 자체는 의미 있음)
				fmt.Printf("warn: cluster_role %s not found: %v\n", b.RoleName, err)
			}
			match.RoleRules = rules
		}

		out = append(out, match)
	}

	return out, nil
}

// ListRoleBindingsForSA는 namespace 한정 RoleBinding을 찾습니다.
func (r *AttackPathRepo) ListRoleBindingsForSA(
	ctx context.Context,
	clusterName, saNamespace, saName string,
	rbSnapshot, rSnapshot, crSnapshot time.Time,
) ([]RoleBindingMatch, error) {

	if rbSnapshot.IsZero() {
		return nil, nil
	}

	// RoleBinding은 namespace 한정. SA와 같은 namespace의 RoleBinding만 찾기.
	query := `
		SELECT 
			rb.name AS binding_name,
			rb.namespace AS binding_namespace,
			rb.role_ref->>'name' AS role_name,
			rb.role_ref->>'kind' AS role_kind
		FROM cluster_role_bindings rb,
		     jsonb_array_elements(rb.subjects) AS subj
		WHERE rb.cluster_name = $1
		  AND rb.snapshot_at = $2
		  AND rb.namespace = $3
		  AND subj->>'kind' = 'ServiceAccount'
		  AND subj->>'name' = $4
		  AND COALESCE(subj->>'namespace', rb.namespace) = $3
	`
	rows, err := r.pool.Query(ctx, query, clusterName, rbSnapshot, saNamespace, saName)
	if err != nil {
		return nil, fmt.Errorf("query rb for SA: %w", err)
	}
	defer rows.Close()

	type bindingRef struct {
		BindingName      string
		BindingNamespace string
		RoleName         string
		RoleKind         string
	}
	var bindings []bindingRef
	for rows.Next() {
		var b bindingRef
		if err := rows.Scan(&b.BindingName, &b.BindingNamespace, &b.RoleName, &b.RoleKind); err != nil {
			return nil, fmt.Errorf("scan rb: %w", err)
		}
		bindings = append(bindings, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 각 binding의 Role 또는 ClusterRole 조회 (RoleBinding은 둘 다 참조 가능)
	var out []RoleBindingMatch
	for _, b := range bindings {
		match := RoleBindingMatch{
			BindingName:  b.BindingName,
			BindingScope: "namespace",
			RoleName:     b.RoleName,
		}

		if b.RoleKind == "ClusterRole" && !crSnapshot.IsZero() {
			rules, err := r.getClusterRoleRules(ctx, clusterName, b.RoleName, crSnapshot)
			if err != nil {
				fmt.Printf("warn: cluster_role %s not found: %v\n", b.RoleName, err)
			}
			match.RoleScope = "cluster"
			match.RoleRules = rules
		} else if !rSnapshot.IsZero() {
			rules, err := r.getRoleRules(ctx, clusterName, b.BindingNamespace, b.RoleName, rSnapshot)
			if err != nil {
				fmt.Printf("warn: role %s/%s not found: %v\n", b.BindingNamespace, b.RoleName, err)
			}
			match.RoleScope = "namespace"
			match.RoleRules = rules
		}

		out = append(out, match)
	}

	return out, nil
}

// getClusterRoleRules는 ClusterRole의 rules를 조회합니다.
func (r *AttackPathRepo) getClusterRoleRules(ctx context.Context, clusterName, roleName string, snapshot time.Time) ([]RoleRule, error) {
	var rulesRaw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT COALESCE(rules, '[]'::jsonb)
		 FROM cluster_cluster_roles
		 WHERE cluster_name = $1 AND snapshot_at = $2 AND name = $3
		 LIMIT 1`,
		clusterName, snapshot, roleName,
	).Scan(&rulesRaw)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return parseRules(rulesRaw), nil
}

// getRoleRules는 namespace Role의 rules를 조회합니다.
func (r *AttackPathRepo) getRoleRules(ctx context.Context, clusterName, namespace, roleName string, snapshot time.Time) ([]RoleRule, error) {
	var rulesRaw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT COALESCE(rules, '[]'::jsonb)
		 FROM cluster_roles
		 WHERE cluster_name = $1 AND snapshot_at = $2 AND namespace = $3 AND name = $4
		 LIMIT 1`,
		clusterName, snapshot, namespace, roleName,
	).Scan(&rulesRaw)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return parseRules(rulesRaw), nil
}

// parseRules는 RBAC rules JSONB를 RoleRule 슬라이스로 변환합니다.
func parseRules(raw []byte) []RoleRule {
	if len(raw) == 0 {
		return nil
	}

	var rawRules []map[string]interface{}
	if err := json.Unmarshal(raw, &rawRules); err != nil {
		return nil
	}

	out := make([]RoleRule, 0, len(rawRules))
	for _, r := range rawRules {
		rule := RoleRule{}
		if arr, ok := r["apiGroups"].([]interface{}); ok {
			rule.APIGroups = toStringSlice(arr)
		}
		if arr, ok := r["resources"].([]interface{}); ok {
			rule.Resources = toStringSlice(arr)
		}
		if arr, ok := r["verbs"].([]interface{}); ok {
			rule.Verbs = toStringSlice(arr)
		}
		out = append(out, rule)
	}
	return out
}

func toStringSlice(arr []interface{}) []string {
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ─────────────────────────────────────────
// NetworkPolicy 데이터 조회
// ─────────────────────────────────────────

// ListNetworkPoliciesForPod는 Pod에 매핑되는 NetworkPolicy를 찾습니다.
//
// 매핑 로직:
//
//	NetworkPolicy.namespace == Pod.namespace
//	AND NetworkPolicy.podSelector.matchLabels ⊆ Pod.labels
//
// 빈 selector ({})는 namespace 전체 Pod에 적용 (K8s 의미).
func (r *AttackPathRepo) ListNetworkPoliciesForPod(
	ctx context.Context,
	clusterName, podNamespace string,
	podLabels map[string]string,
	snapshot time.Time,
) ([]NetworkPolicyMatch, error) {

	if snapshot.IsZero() {
		return nil, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT 
			name, 
			COALESCE(pod_selector, '{}'::jsonb) AS pod_selector,
			COALESCE(policy_types, '[]'::jsonb) AS policy_types
		 FROM cluster_network_policies
		 WHERE cluster_name = $1 AND snapshot_at = $2 AND namespace = $3`,
		clusterName, snapshot, podNamespace,
	)
	if err != nil {
		return nil, fmt.Errorf("query netpol: %w", err)
	}
	defer rows.Close()

	var out []NetworkPolicyMatch
	for rows.Next() {
		var name string
		var selectorRaw, typesRaw []byte
		if err := rows.Scan(&name, &selectorRaw, &typesRaw); err != nil {
			return nil, fmt.Errorf("scan netpol: %w", err)
		}

		// podSelector.matchLabels 추출 → Pod labels와 매칭 확인
		var selectorObj map[string]interface{}
		_ = json.Unmarshal(selectorRaw, &selectorObj)

		matchLabels := map[string]string{}
		if ml, ok := selectorObj["matchLabels"].(map[string]interface{}); ok {
			for k, v := range ml {
				if s, ok := v.(string); ok {
					matchLabels[k] = s
				}
			}
		}

		// 빈 selector는 namespace 전체 적용
		// 비어있지 않으면 subset 검사
		if len(matchLabels) > 0 {
			if !labelsSubset(matchLabels, podLabels) {
				continue
			}
		}

		var types []string
		_ = json.Unmarshal(typesRaw, &types)

		out = append(out, NetworkPolicyMatch{
			Name:        name,
			Namespace:   podNamespace,
			PolicyTypes: types,
		})
	}
	return out, rows.Err()
}

// labelsSubset은 sel의 모든 key/value가 pod에 포함되어 있는지 확인합니다.
func labelsSubset(sel, pod map[string]string) bool {
	for k, v := range sel {
		if pod[k] != v {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────
// 결과 저장
// ─────────────────────────────────────────

// UpsertBatch는 attack_path_scores에 batch로 저장합니다.
func (r *AttackPathRepo) UpsertBatch(ctx context.Context, results []scoring.AttackPathResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO attack_path_scores (
			cluster_name, pod_uid, pod_name, pod_namespace,
			total_score, rbac_score, network_score, mount_score,
			rbac_details, network_details, mount_details,
			snapshot_at,
			runtime_network_score, runtime_network_details,
			uses_host_network,
			overgrant_ratio, overgranted_permissions
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17
		)
		ON CONFLICT (cluster_name, pod_uid, snapshot_at) DO UPDATE SET
			pod_name                = EXCLUDED.pod_name,
			pod_namespace           = EXCLUDED.pod_namespace,
			total_score             = EXCLUDED.total_score,
			rbac_score              = EXCLUDED.rbac_score,
			network_score           = EXCLUDED.network_score,
			mount_score             = EXCLUDED.mount_score,
			rbac_details            = EXCLUDED.rbac_details,
			network_details         = EXCLUDED.network_details,
			mount_details           = EXCLUDED.mount_details,
			runtime_network_score   = EXCLUDED.runtime_network_score,
			runtime_network_details = EXCLUDED.runtime_network_details,
			uses_host_network       = EXCLUDED.uses_host_network,
			overgrant_ratio         = EXCLUDED.overgrant_ratio,
			overgranted_permissions = EXCLUDED.overgranted_permissions,
			computed_at             = NOW()
	`

	for _, res := range results {
		rbacJSON, _ := json.Marshal(res.RBACDetails)
		netJSON, _ := json.Marshal(res.NetworkDetails)
		mountJSON, _ := json.Marshal(res.MountDetails)

		// nullable JSONB — nil이면 NULL로 들어감
		var runtimeNetDetailsJSON, overgrantedJSON []byte
		if res.RuntimeNetworkDetails != nil {
			runtimeNetDetailsJSON, _ = json.Marshal(res.RuntimeNetworkDetails)
		}
		if res.OvergrantedPermissions != nil {
			overgrantedJSON, _ = json.Marshal(res.OvergrantedPermissions)
		}

		_, err := tx.Exec(ctx, q,
			res.ClusterName, res.PodUID, res.PodName, res.PodNamespace,
			res.TotalScore, res.RBACScore, res.NetworkScore, res.MountScore,
			rbacJSON, netJSON, mountJSON,
			res.SnapshotAt,
			res.RuntimeNetworkScore, runtimeNetDetailsJSON,
			res.UsesHostNetwork,
			res.OvergrantRatio, overgrantedJSON,
		)
		if err != nil {
			return fmt.Errorf("upsert pod %s: %w", res.PodUID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetByPodUID는 단일 Pod의 최근 결과를 조회합니다.
func (r *AttackPathRepo) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.AttackPathResult, error) {
	var res scoring.AttackPathResult
	var rbacRaw, netRaw, mountRaw []byte

	err := r.pool.QueryRow(ctx,
		`SELECT 
			cluster_name, pod_uid, pod_name, pod_namespace,
			total_score, rbac_score, network_score, mount_score,
			rbac_details, network_details, mount_details,
			snapshot_at, computed_at
		 FROM attack_path_scores
		 WHERE cluster_name = $1 AND pod_uid = $2
		 ORDER BY snapshot_at DESC LIMIT 1`,
		clusterName, podUID,
	).Scan(
		&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
		&res.TotalScore, &res.RBACScore, &res.NetworkScore, &res.MountScore,
		&rbacRaw, &netRaw, &mountRaw,
		&res.SnapshotAt, &res.ComputedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get by pod uid: %w", err)
	}

	_ = json.Unmarshal(rbacRaw, &res.RBACDetails)
	_ = json.Unmarshal(netRaw, &res.NetworkDetails)
	_ = json.Unmarshal(mountRaw, &res.MountDetails)

	return &res, nil
}

// ListByCluster는 클러스터의 최신 결과를 모두 반환합니다.
func (r *AttackPathRepo) ListByCluster(ctx context.Context, clusterName string) ([]scoring.AttackPathResult, error) {
	var latestSnapshot *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT MAX(snapshot_at) FROM attack_path_scores WHERE cluster_name = $1`,
		clusterName,
	).Scan(&latestSnapshot)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get latest snapshot: %w", err)
	}
	if latestSnapshot == nil {
		return []scoring.AttackPathResult{}, nil
	}

	rows, err := r.pool.Query(ctx,
		`SELECT 
			cluster_name, pod_uid, pod_name, pod_namespace,
			total_score, rbac_score, network_score, mount_score,
			rbac_details, network_details, mount_details,
			snapshot_at, computed_at
		 FROM attack_path_scores
		 WHERE cluster_name = $1 AND snapshot_at = $2
		 ORDER BY total_score DESC, pod_namespace, pod_name`,
		clusterName, *latestSnapshot,
	)
	if err != nil {
		return nil, fmt.Errorf("list by cluster: %w", err)
	}
	defer rows.Close()

	var out []scoring.AttackPathResult
	for rows.Next() {
		var res scoring.AttackPathResult
		var rbacRaw, netRaw, mountRaw []byte
		err := rows.Scan(
			&res.ClusterName, &res.PodUID, &res.PodName, &res.PodNamespace,
			&res.TotalScore, &res.RBACScore, &res.NetworkScore, &res.MountScore,
			&rbacRaw, &netRaw, &mountRaw,
			&res.SnapshotAt, &res.ComputedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan result: %w", err)
		}

		_ = json.Unmarshal(rbacRaw, &res.RBACDetails)
		_ = json.Unmarshal(netRaw, &res.NetworkDetails)
		_ = json.Unmarshal(mountRaw, &res.MountDetails)

		out = append(out, res)
	}
	return out, rows.Err()
}
