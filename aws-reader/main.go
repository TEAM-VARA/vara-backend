package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"net/http"
	"os"
	"time"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/aws/aws-sdk-go-v2/service/eks"
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

type eksAccessEntry struct {
	PrincipalArn string `json:"principal_arn"`
}

type eksAccessConfigPayload struct {
	AccountID          string           `json:"account_id"`
	Region             string           `json:"region"`
	SnapshotAt         time.Time        `json:"snapshot_at"`
	ClusterName        string           `json:"cluster_name"`
	AuthenticationMode string           `json:"authentication_mode"`
	AccessEntries      []eksAccessEntry `json:"access_entries"`
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
	iamClient := iam.NewFromConfig(cfg)
	eksClient := eks.NewFromConfig(cfg)
	clusterName := getenv("EKS_CLUSTER_NAME", "vara-test-eks")

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
		if err := collectAndSendIam(ctx, iamClient, backendURL, accountID); err != nil {
			log.Printf("[iam] error: %v", err)
		}
		if err := collectAndSendEksAccess(ctx, eksClient, backendURL, accountID, region, clusterName); err != nil {
		log.Printf("[eks] error: %v", err)
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

// ───────────────────────── IAM Authorization ─────────────────────────
// 기존 SG/KMS/CloudTrail 과 다른 점:
//   1) payload 에 Region 없음 (IAM 은 글로벌)
//   2) 응답 원소를 필드별로 매핑하지 않고 통째로 Marshal (RawMessage 로 전송)
//   3) Marshal 전에 정책 문서 URL 디코딩 필수 (Go SDK 는 자동 디코딩 안 함)
type iamPayload struct {
	AccountID    string          `json:"account_id"`
	AccountAlias string          `json:"account_alias"`
	Partition    string          `json:"partition"`
	SnapshotAt   time.Time       `json:"snapshot_at"`
	CapturedBy   string          `json:"captured_by"`
	UserDetailList  json.RawMessage `json:"user_detail_list"`
	RoleDetailList  json.RawMessage `json:"role_detail_list"`
	GroupDetailList json.RawMessage `json:"group_detail_list"`
	Policies        json.RawMessage `json:"policies"`
}

func collectAndSendIam(ctx context.Context, ic *iam.Client, backendURL, accountID string) error {
	// 4종 리스트를 페이지네이션 끝까지 누적
	var users, roles, groups, policies []any
	pager := iam.NewGetAccountAuthorizationDetailsPaginator(ic,
		&iam.GetAccountAuthorizationDetailsInput{
			Filter: []iamtypes.EntityType{
				iamtypes.EntityTypeUser, iamtypes.EntityTypeRole, iamtypes.EntityTypeGroup,
				iamtypes.EntityTypeLocalManagedPolicy, iamtypes.EntityTypeAWSManagedPolicy,
			},
		})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		users = append(users, toDecodedJSON(page.UserDetailList)...)
		roles = append(roles, toDecodedJSON(page.RoleDetailList)...)
		groups = append(groups, toDecodedJSON(page.GroupDetailList)...)
		policies = append(policies, toDecodedJSON(page.Policies)...)
	}

	body := iamPayload{
		AccountID:       accountID,
		SnapshotAt:      time.Now().UTC(),
		CapturedBy:      "iam-agent/1.0",
		UserDetailList:  ensureArray(users),
		RoleDetailList:  ensureArray(roles),
		GroupDetailList: ensureArray(groups),
		Policies:        ensureArray(policies),
	}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(backendURL+"/api/v1/agents/aws-reader/iam-authorization", "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend status %d", resp.StatusCode)
	}
	log.Printf("[iam] sent: users=%d roles=%d groups=%d policies=%d",
		len(users), len(roles), len(groups), len(policies))
	return nil
}

// SDK 구조체를 generic JSON 으로 바꾼 뒤, 정책 문서 문자열을 객체로 펼친다.
func toDecodedJSON(v any) []any {
	b, _ := json.Marshal(v)
	var arr []any
	_ = json.Unmarshal(b, &arr)
	for i := range arr {
		arr[i] = decodeDocs(arr[i])
	}
	return arr
}

// PolicyDocument / Document / AssumeRolePolicyDocument 의 URL 인코딩 문자열을
// JSON 객체로 디코딩(재귀). ← Go SDK 가 안 풀어주는 그 함정 처리.
func decodeDocs(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok &&
				(k == "PolicyDocument" || k == "Document" || k == "AssumeRolePolicyDocument") {
				if dec, e := url.QueryUnescape(s); e == nil {
					var obj any
					if json.Unmarshal([]byte(dec), &obj) == nil {
						x[k] = obj
						continue
					}
				}
			}
			x[k] = decodeDocs(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = decodeDocs(x[i])
		}
		return x
	}
	return v
}

// nil 슬라이스를 JSON "[]" 로 강제 (테이블 CHECK chk_*_is_array 통과용).
// var arr []any 를 그냥 Marshal 하면 "null" → CHECK 위반으로 INSERT 터짐.
func ensureArray(v []any) json.RawMessage {
	if v == nil {
		return json.RawMessage("[]")
	}
	b, _ := json.Marshal(v)
	return b
}

func collectAndSendEksAccess(ctx context.Context, ec *eks.Client, backendURL, accountID, region, clusterName string) error {
	// 1) 클러스터 인증 모드
	desc, err := ec.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &clusterName})
	if err != nil {
		return fmt.Errorf("describe cluster: %w", err)
	}
	authMode := ""
	if desc.Cluster != nil && desc.Cluster.AccessConfig != nil {
		authMode = string(desc.Cluster.AccessConfig.AuthenticationMode)
	}

	// 2) access entry 목록 (페이지네이션)
	var entries []eksAccessEntry
	pager := eks.NewListAccessEntriesPaginator(ec, &eks.ListAccessEntriesInput{ClusterName: &clusterName})
	for pager.HasMorePages() {
		out, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list access entries: %w", err)
		}
		for _, arn := range out.AccessEntries {
			entries = append(entries, eksAccessEntry{PrincipalArn: arn})
		}
	}

	body := eksAccessConfigPayload{
		AccountID:          accountID,
		Region:             region,
		SnapshotAt:         time.Now().UTC(),
		ClusterName:        clusterName,
		AuthenticationMode: authMode,
		AccessEntries:      entries,
	}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(backendURL+"/api/v1/agents/aws-reader/eks-access-config", "application/json", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	log.Printf("[eks] sent: authMode=%s, entries=%d", authMode, len(entries))
	return nil
}