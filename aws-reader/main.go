package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

type sgRule map[string]interface{}

type securityGroup struct {
	GroupID      string   `json:"group_id"`
	GroupName    string   `json:"group_name"`
	VpcID        string   `json:"vpc_id"`
	Description  string   `json:"description"`
	IngressRules []sgRule `json:"ingress_rules"`
	EgressRules  []sgRule `json:"egress_rules"`
}

type payload struct {
	AccountID      string          `json:"account_id"`
	Region         string          `json:"region"`
	SnapshotAt     time.Time       `json:"snapshot_at"`
	SecurityGroups []securityGroup `json:"security_groups"`
}

type kmsKey struct {
	KeyID           string     `json:"key_id"`
	Arn             string     `json:"arn"`
	KeyState        string     `json:"key_state"`
	KeyManager      string     `json:"key_manager"`
	KeySpec         string     `json:"key_spec"`
	Enabled         *bool      `json:"enabled"`
	RotationEnabled *bool      `json:"rotation_enabled"`
	Description     string     `json:"description"`
	CreationDate    *time.Time `json:"creation_date"`
}

type kmsPayload struct {
	AccountID  string    `json:"account_id"`
	Region     string    `json:"region"`
	SnapshotAt time.Time `json:"snapshot_at"`
	Keys       []kmsKey  `json:"keys"`
}

type cloudTrailTrail struct {
	Name                     string `json:"name"`
	TrailArn                 string `json:"trail_arn"`
	HomeRegion               string `json:"home_region"`
	S3Bucket                 string `json:"s3_bucket"`
	IsMultiRegion            *bool  `json:"is_multi_region"`
	IncludeGlobalEvents      *bool  `json:"include_global_events"`
	KmsKeyID                 string `json:"kms_key_id"`
	LogFileValidationEnabled *bool  `json:"log_file_validation_enabled"`
	IsLogging                *bool  `json:"is_logging"`
}

type cloudTrailPayload struct {
	AccountID  string            `json:"account_id"`
	Region     string            `json:"region"`
	SnapshotAt time.Time         `json:"snapshot_at"`
	Trails     []cloudTrailTrail `json:"trails"`
}

func main() {
	backendURL := getenv("BACKEND_URL", "http://backend:8080")
	region := getenv("AWS_REGION", "ap-northeast-2")
	interval := 5 * time.Minute
	if v := os.Getenv("INTERVAL_MINUTES"); v != "" {
		if d, err := time.ParseDuration(v + "m"); err == nil {
			interval = d
		}
	}

	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		log.Fatalf("aws config: %v", err)
	}

	accountID := ""
	if out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		accountID = aws.ToString(out.Account)
	}
	ec2c := ec2.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	ctClient := cloudtrail.NewFromConfig(cfg)

	log.Printf("aws-reader starting (region=%s, account=%s, backend=%s, interval=%s)", region, accountID, backendURL, interval)

	run := func() {
		if err := collectAndSend(ctx, ec2c, backendURL, accountID, region); err != nil {
			log.Printf("[sg] error: %v", err)
		}
		if err := collectAndSendKms(ctx, kmsClient, backendURL, accountID, region); err != nil {
			log.Printf("[kms] error: %v", err)
		}
		if err := collectAndSendCloudTrail(ctx, ctClient, backendURL, accountID, region); err != nil {
			log.Printf("[cloudtrail] error: %v", err)
		}
	}
	run() // 즉시 1회
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		run()
	}
}

func collectAndSend(ctx context.Context, ec2c *ec2.Client, backendURL, accountID, region string) error {
	var groups []securityGroup
	p := ec2.NewDescribeSecurityGroupsPaginator(ec2c, &ec2.DescribeSecurityGroupsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, g := range page.SecurityGroups {
			groups = append(groups, securityGroup{
				GroupID:      aws.ToString(g.GroupId),
				GroupName:    aws.ToString(g.GroupName),
				VpcID:        aws.ToString(g.VpcId),
				Description:  aws.ToString(g.Description),
				IngressRules: mapRules(g.IpPermissions),
				EgressRules:  mapRules(g.IpPermissionsEgress),
			})
		}
	}

	body := payload{AccountID: accountID, Region: region, SnapshotAt: time.Now().UTC(), SecurityGroups: groups}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(backendURL+"/api/v1/agents/aws-reader/security-groups", "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend status %d", resp.StatusCode)
	}
	log.Printf("[sg] sent: %d groups", len(groups))
	return nil
}

func mapRules(perms []ec2types.IpPermission) []sgRule {
	rules := []sgRule{}
	for _, p := range perms {
		cidrs := []string{}
		for _, r := range p.IpRanges {
			cidrs = append(cidrs, aws.ToString(r.CidrIp))
		}
		rules = append(rules, sgRule{
			"protocol":  aws.ToString(p.IpProtocol),
			"from_port": aws.ToInt32(p.FromPort),
			"to_port":   aws.ToInt32(p.ToPort),
			"cidrs":     cidrs,
		})
	}
	return rules
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func collectAndSendKms(ctx context.Context, kc *kms.Client, backendURL, accountID, region string) error {
	var keys []kmsKey
	p := kms.NewListKeysPaginator(kc, &kms.ListKeysInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, entry := range page.Keys {
			keyID := aws.ToString(entry.KeyId)

			// 1) DescribeKey → 메타데이터
			desc, err := kc.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: entry.KeyId})
			if err != nil {
				log.Printf("[kms] describe %s: %v", keyID, err)
				continue
			}
			md := desc.KeyMetadata

			k := kmsKey{
				KeyID:        keyID,
				Arn:          aws.ToString(md.Arn),
				KeyState:     string(md.KeyState),
				KeyManager:   string(md.KeyManager),
				KeySpec:      string(md.KeySpec),
				Enabled:      aws.Bool(md.Enabled),
				Description:  aws.ToString(md.Description),
				CreationDate: md.CreationDate,
			}

			// 2) GetKeyRotationStatus → 자동 교체 여부 (실패하면 nil 유지)
			if rot, err := kc.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: entry.KeyId}); err == nil {
				k.RotationEnabled = aws.Bool(rot.KeyRotationEnabled)
			}

			keys = append(keys, k)
		}
	}

	body := kmsPayload{AccountID: accountID, Region: region, SnapshotAt: time.Now().UTC(), Keys: keys}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(backendURL+"/api/v1/agents/aws-reader/kms-keys", "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend status %d", resp.StatusCode)
	}
	log.Printf("[kms] sent: %d keys", len(keys))
	return nil
}

func collectAndSendCloudTrail(ctx context.Context, ctc *cloudtrail.Client, backendURL, accountID, region string) error {
	out, err := ctc.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return err
	}

	var trails []cloudTrailTrail
	for _, t := range out.TrailList {
		ct := cloudTrailTrail{
			Name:                     aws.ToString(t.Name),
			TrailArn:                 aws.ToString(t.TrailARN),
			HomeRegion:               aws.ToString(t.HomeRegion),
			S3Bucket:                 aws.ToString(t.S3BucketName),
			IsMultiRegion:            t.IsMultiRegionTrail,
			IncludeGlobalEvents:      t.IncludeGlobalServiceEvents,
			KmsKeyID:                 aws.ToString(t.KmsKeyId),
			LogFileValidationEnabled: t.LogFileValidationEnabled,
		}

		// GetTrailStatus → 실제 로깅 중인지 (실패하면 nil 유지)
		if st, err := ctc.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}); err == nil {
			ct.IsLogging = st.IsLogging
		} else {
			log.Printf("[cloudtrail] status %s: %v", aws.ToString(t.Name), err)
		}

		trails = append(trails, ct)
	}

	body := cloudTrailPayload{AccountID: accountID, Region: region, SnapshotAt: time.Now().UTC(), Trails: trails}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(backendURL+"/api/v1/agents/aws-reader/cloudtrail-trails", "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend status %d", resp.StatusCode)
	}
	log.Printf("[cloudtrail] sent: %d trails", len(trails))
	return nil
}