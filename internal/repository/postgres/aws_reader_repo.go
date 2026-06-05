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