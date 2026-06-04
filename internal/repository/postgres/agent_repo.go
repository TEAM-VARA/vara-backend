// GRC 보조: Pod 라이프사이클 이벤트, SBOM(Trivy), eBPF 트래픽 데이터를 저장.
// GRC 자산 인벤토리(Finding F-1.2.1-K8S-01)와 이미지 취약점 평가(F-2.10.8-K8S-04)에
// 활용되는 원시 데이터를 제공한다.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/agent"
)

type AgentRepo struct {
	pg *pgxpool.Pool
}

func NewAgentRepo(pg *pgxpool.Pool) *AgentRepo {
	return &AgentRepo{pg: pg}
}

// UpsertPod : pod_added 이벤트
func (r *AgentRepo) UpsertPod(ctx context.Context, e agent.PodEvent) error {
	const q = `
		INSERT INTO pods
		  (pod_uid, pod_name, namespace, node_name, ip, image, image_digest, updated_at, deleted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NULL)
		ON CONFLICT (pod_uid) DO UPDATE SET
		  pod_name     = EXCLUDED.pod_name,
		  namespace    = EXCLUDED.namespace,
		  node_name    = EXCLUDED.node_name,
		  ip           = EXCLUDED.ip,
		  image        = EXCLUDED.image,
		  image_digest = EXCLUDED.image_digest,
		  updated_at   = NOW(),
		  deleted_at   = NULL
	`
	_, err := r.pg.Exec(ctx, q,
		e.PodUID, e.PodName, e.Namespace, e.NodeName,
		e.IP, e.Image, e.ImageDigest,
	)
	if err != nil {
		return fmt.Errorf("upsert pod: %w", err)
	}
	return nil
}

// MarkPodDeleted : pod_deleted 이벤트 (soft delete)
func (r *AgentRepo) MarkPodDeleted(ctx context.Context, podUID string) error {
	const q = `
		UPDATE pods SET deleted_at = NOW(), updated_at = NOW()
		WHERE pod_uid = $1 AND deleted_at IS NULL
	`
	_, err := r.pg.Exec(ctx, q, podUID)
	return err
}

// UpsertSBOM : SBOM + CVE 일괄 등록 (트랜잭션)
func (r *AgentRepo) UpsertSBOM(ctx context.Context, req agent.SBOMRequest) (int, error) {
	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	rawJSON, _ := json.Marshal(req.RawData)
	const sbomQ = `
		INSERT INTO sboms (image, image_digest, raw_data)
		VALUES ($1, $2, $3)
		ON CONFLICT (image_digest) DO UPDATE SET
		  image    = EXCLUDED.image,
		  raw_data = EXCLUDED.raw_data
	`
	if _, err := tx.Exec(ctx, sbomQ, req.Image, req.ImageDigest, rawJSON); err != nil {
		return 0, fmt.Errorf("upsert sbom: %w", err)
	}

	const cveQ = `
		INSERT INTO cves (image_digest, cve_id, severity,
		                  package_name, installed_version, fixed_version, cvss_score)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (image_digest, cve_id) DO UPDATE SET
		  severity          = EXCLUDED.severity,
		  package_name      = EXCLUDED.package_name,
		  installed_version = EXCLUDED.installed_version,
		  fixed_version     = EXCLUDED.fixed_version,
		  cvss_score        = EXCLUDED.cvss_score
	`
	for _, cve := range req.CVEs {
		_, err := tx.Exec(ctx, cveQ,
			req.ImageDigest, cve.CVEID, cve.Severity,
			cve.PackageName, cve.InstalledVersion, cve.FixedVersion, cve.CVSSScore,
		)
		if err != nil {
			return 0, fmt.Errorf("upsert cve %s: %w", cve.CVEID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("tx commit: %w", err)
	}
	return len(req.CVEs), nil
}

// InsertTraffic : 트래픽 일괄 INSERT
func (r *AgentRepo) InsertTraffic(ctx context.Context, events []agent.TrafficEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	const q = `
		INSERT INTO traffic (ts, src_ip, dst_ip, bytes, packets)
		VALUES ($1, $2, $3, $4, $5)
	`
	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	for _, e := range events {
		_, err := tx.Exec(ctx, q, e.Timestamp, e.SrcIP, e.DstIP, e.Bytes, e.Packets)
		if err != nil {
			return 0, fmt.Errorf("insert traffic: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(events), nil
}
