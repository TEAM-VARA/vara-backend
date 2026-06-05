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

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	log.Printf("aws-reader starting (region=%s, account=%s, backend=%s, interval=%s)", region, accountID, backendURL, interval)

	run := func() {
		if err := collectAndSend(ctx, ec2c, backendURL, accountID, region); err != nil {
			log.Printf("[sg] error: %v", err)
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