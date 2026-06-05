package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vara/backend/internal/domain/agent"
)

type AwsReaderRepo struct {
	pool *pgxpool.Pool
}

func NewAwsReaderRepo(pool *pgxpool.Pool) *AwsReaderRepo {
	return &AwsReaderRepo{pool: pool}
}

func (r *AwsReaderRepo) UpsertSecurityGroups(ctx context.Context, req agent.AwsSecurityGroupsRequest) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO aws_security_groups (
			account_id, region, snapshot_at,
			group_id, group_name, vpc_id, description,
			ingress_rules, egress_rules
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
		ON CONFLICT (account_id, region, snapshot_at, group_id) DO UPDATE SET
			group_name    = EXCLUDED.group_name,
			vpc_id        = EXCLUDED.vpc_id,
			description   = EXCLUDED.description,
			ingress_rules = EXCLUDED.ingress_rules,
			egress_rules  = EXCLUDED.egress_rules
	`
	saved := 0
	for _, sg := range req.SecurityGroups {
		ingressJSON, _ := json.Marshal(sg.IngressRules)
		egressJSON, _ := json.Marshal(sg.EgressRules)
		if _, err := tx.Exec(ctx, q,
			req.AccountID, req.Region, req.SnapshotAt,
			sg.GroupID, sg.GroupName, sg.VpcID, sg.Description,
			ingressJSON, egressJSON,
		); err != nil {
			return saved, fmt.Errorf("upsert sg %s: %w", sg.GroupID, err)
		}
		saved++
	}
	if err := tx.Commit(ctx); err != nil {
		return saved, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}


func (r *AwsReaderRepo) UpsertKmsKeys(ctx context.Context, req agent.AwsKmsKeysRequest) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO aws_kms_keys (
			account_id, region, snapshot_at,
			key_id, arn, key_state, key_manager, key_spec,
			enabled, rotation_enabled, description, creation_date
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (account_id, region, snapshot_at, key_id) DO UPDATE SET
			arn              = EXCLUDED.arn,
			key_state        = EXCLUDED.key_state,
			key_manager      = EXCLUDED.key_manager,
			key_spec         = EXCLUDED.key_spec,
			enabled          = EXCLUDED.enabled,
			rotation_enabled = EXCLUDED.rotation_enabled,
			description      = EXCLUDED.description,
			creation_date    = EXCLUDED.creation_date
	`
	saved := 0
	for _, k := range req.Keys {
		if _, err := tx.Exec(ctx, q,
			req.AccountID, req.Region, req.SnapshotAt,
			k.KeyID, k.Arn, k.KeyState, k.KeyManager, k.KeySpec,
			k.Enabled, k.RotationEnabled, k.Description, k.CreationDate,
		); err != nil {
			return saved, fmt.Errorf("upsert kms %s: %w", k.KeyID, err)
		}
		saved++
	}
	if err := tx.Commit(ctx); err != nil {
		return saved, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}

func (r *AwsReaderRepo) UpsertCloudTrailTrails(ctx context.Context, req agent.AwsCloudTrailTrailsRequest) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO aws_cloudtrail_trails (
			account_id, region, snapshot_at,
			name, trail_arn, home_region, s3_bucket,
			is_multi_region, include_global_events, kms_key_id,
			log_file_validation_enabled, is_logging
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (account_id, region, snapshot_at, trail_arn) DO UPDATE SET
			name                        = EXCLUDED.name,
			home_region                 = EXCLUDED.home_region,
			s3_bucket                   = EXCLUDED.s3_bucket,
			is_multi_region             = EXCLUDED.is_multi_region,
			include_global_events       = EXCLUDED.include_global_events,
			kms_key_id                  = EXCLUDED.kms_key_id,
			log_file_validation_enabled = EXCLUDED.log_file_validation_enabled,
			is_logging                  = EXCLUDED.is_logging
	`
	saved := 0
	for _, t := range req.Trails {
		if _, err := tx.Exec(ctx, q,
			req.AccountID, req.Region, req.SnapshotAt,
			t.Name, t.TrailArn, t.HomeRegion, t.S3Bucket,
			t.IsMultiRegion, t.IncludeGlobalEvents, t.KmsKeyID,
			t.LogFileValidationEnabled, t.IsLogging,
		); err != nil {
			return saved, fmt.Errorf("upsert trail %s: %w", t.TrailArn, err)
		}
		saved++
	}
	if err := tx.Commit(ctx); err != nil {
		return saved, fmt.Errorf("commit: %w", err)
	}
	return saved, nil
}