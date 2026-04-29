package main

// AWS RDS 자산/노출도 수집기.
// IRSA (IAM Roles for Service Accounts) 또는 EC2 인스턴스 프로파일을 통해 자격증명을 자동 로드한다.
// PubliclyAccessible=true 인 RDS 인스턴스는 E4 노출로 등록한다.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type AWSCollector struct {
	rdsClient *rds.Client
	region    string
	cluster   string
}

func NewAWSCollector(ctx context.Context, region, cluster string) (*AWSCollector, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return &AWSCollector{
		rdsClient: rds.NewFromConfig(cfg),
		region:    region,
		cluster:   cluster,
	}, nil
}

// CollectRDS는 region 내 모든 RDS 인스턴스를 자산으로 등록하고,
// PubliclyAccessible 인 경우 외부 노출 정보(E4)를 함께 등록한다.
func (a *AWSCollector) CollectRDS(ctx context.Context) ([]Asset, []Exposure, error) {
	assets := []Asset{}
	exposures := []Exposure{}

	paginator := rds.NewDescribeDBInstancesPaginator(a.rdsClient, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("describe rds: %w", err)
		}
		for i := range page.DBInstances {
			db := &page.DBInstances[i]
			id := aws.ToString(db.DBInstanceIdentifier)
			assetID := rdsAssetID(a.region, id)

			endpoint := ""
			port := 0
			if db.Endpoint != nil {
				endpoint = aws.ToString(db.Endpoint.Address)
				port = int(aws.ToInt32(db.Endpoint.Port))
			}

			assets = append(assets, Asset{
				AssetID:       assetID,
				AssetType:     "rds",
				Name:          id,
				Cluster:       a.cluster,
				CloudProvider: "aws",
				Metadata: map[string]any{
					"engine":                          aws.ToString(db.Engine),
					"engine_version":                  aws.ToString(db.EngineVersion),
					"instance_class":                  aws.ToString(db.DBInstanceClass),
					"publicly_accessible":             aws.ToBool(db.PubliclyAccessible),
					"storage_encrypted":               aws.ToBool(db.StorageEncrypted),
					"iam_db_auth_enabled":             aws.ToBool(db.IAMDatabaseAuthenticationEnabled),
					"deletion_protection":             aws.ToBool(db.DeletionProtection),
					"multi_az":                        aws.ToBool(db.MultiAZ),
					"backup_retention_period_days":    int(aws.ToInt32(db.BackupRetentionPeriod)),
					"vpc_security_group_ids":          vpcSecurityGroupIDs(db.VpcSecurityGroups),
					"db_subnet_group":                 subnetGroupName(db.DBSubnetGroup),
					"endpoint":                        endpoint,
					"port":                            port,
				},
			})

			if aws.ToBool(db.PubliclyAccessible) {
				exposures = append(exposures, Exposure{
					AssetID:       assetID,
					ExposureLevel: "E4",
					ExposureType:  "aws_rds_public",
					Entrypoint:    endpoint,
					Protocol:      "tcp",
					Port:          port,
					AuthRequired:  true, // RDS 인증 자체는 필수 — 다만 공인 IP 도달 가능성이 문제.
					Description: fmt.Sprintf(
						"RDS 인스턴스 %s 가 PubliclyAccessible=true 로 인터넷에서 도달 가능하다. endpoint=%s port=%d",
						id, endpoint, port,
					),
					Metadata: map[string]any{
						"engine":                 aws.ToString(db.Engine),
						"vpc_security_group_ids": vpcSecurityGroupIDs(db.VpcSecurityGroups),
					},
				})
			}
		}
	}

	return assets, exposures, nil
}

func vpcSecurityGroupIDs(sgs []rdstypes.VpcSecurityGroupMembership) []string {
	out := make([]string, 0, len(sgs))
	for _, sg := range sgs {
		out = append(out, aws.ToString(sg.VpcSecurityGroupId))
	}
	return out
}

func subnetGroupName(sg *rdstypes.DBSubnetGroup) string {
	if sg == nil {
		return ""
	}
	return aws.ToString(sg.DBSubnetGroupName)
}

func rdsAssetID(region, id string) string {
	return fmt.Sprintf("rds://%s/%s", region, id)
}
