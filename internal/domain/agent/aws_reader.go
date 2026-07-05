package agent

import (
	"time"
	"encoding/json"
)

// ───────────────────────── IAM Authorization Snapshot ─────────────────────────
// 기존 SG/KMS/CloudTrail 과 다른 점:
//   - Region 필드 없음 (IAM 은 글로벌 서비스)
//   - 엔티티 슬라이스가 아니라 4개 리스트를 통째로 받음 → 계정당 1행
//   - 정책 문서는 에이전트(reader)가 URL 디코딩 완료한 JSON 객체 상태로 보냄
//     (백엔드는 받은 그대로 JSONB 적재. 디코딩 책임은 reader 에 있음)
type AwsIamAuthorizationRequest struct {
	AccountID    string          `json:"account_id" binding:"required"`
	AccountAlias string          `json:"account_alias"`
	Partition    string          `json:"partition"` // 비면 repo 에서 'aws' 기본값
	SnapshotAt   time.Time       `json:"snapshot_at" binding:"required"`
	CapturedBy   string          `json:"captured_by"`

	// 4종 리스트. reader 가 이미 []byte(JSON 배열)로 만들어 보내므로 RawMessage 로 받는다.
	// → 백엔드에서 다시 파싱/가공하지 않고 그대로 JSONB 컬럼에 넘긴다.
	UserDetailList  json.RawMessage `json:"user_detail_list" binding:"required"`
	RoleDetailList  json.RawMessage `json:"role_detail_list" binding:"required"`
	GroupDetailList json.RawMessage `json:"group_detail_list" binding:"required"`
	Policies        json.RawMessage `json:"policies" binding:"required"`
}

type AwsSecurityGroupsRequest struct {
	AccountID      string             `json:"account_id" binding:"required"`
	Region         string             `json:"region" binding:"required"`
	SnapshotAt     time.Time          `json:"snapshot_at" binding:"required"`
	SecurityGroups []AwsSecurityGroup `json:"security_groups" binding:"required,dive"`
}

type AwsSecurityGroup struct {
	GroupID      string                   `json:"group_id" binding:"required"`
	GroupName    string                   `json:"group_name"`
	VpcID        string                   `json:"vpc_id"`
	Description  string                   `json:"description"`
	IngressRules []map[string]interface{} `json:"ingress_rules"`
	EgressRules  []map[string]interface{} `json:"egress_rules"`
}

type AwsKmsKeysRequest struct {
	AccountID  string      `json:"account_id" binding:"required"`
	Region     string      `json:"region" binding:"required"`
	SnapshotAt time.Time   `json:"snapshot_at" binding:"required"`
	Keys       []AwsKmsKey `json:"keys" binding:"required,dive"`
}

type AwsKmsKey struct {
	KeyID           string     `json:"key_id" binding:"required"`
	Arn             string     `json:"arn"`
	KeyState        string     `json:"key_state"`
	KeyManager      string     `json:"key_manager"`   // AWS / CUSTOMER
	KeySpec         string     `json:"key_spec"`
	Enabled         *bool      `json:"enabled"`           // 포인터 = null 허용
	RotationEnabled *bool      `json:"rotation_enabled"`  // AWS관리 키는 unknown일 수 있어서 *bool
	Description     string     `json:"description"`
	CreationDate    *time.Time `json:"creation_date"`
}

type AwsEksAccessConfigRequest struct {
	AccountID          string                `json:"account_id"`
	Region             string                `json:"region"`
	SnapshotAt         time.Time             `json:"snapshot_at"`
	ClusterName        string                `json:"cluster_name" binding:"required"`
	AuthenticationMode string                `json:"authentication_mode"`
	AccessEntries      []AwsEksAccessEntry   `json:"access_entries"`
}

type AwsEksAccessEntry struct {
	PrincipalArn string `json:"principal_arn"`
}

type AwsCloudTrailTrailsRequest struct {
	AccountID  string               `json:"account_id" binding:"required"`
	Region     string               `json:"region" binding:"required"`
	SnapshotAt time.Time            `json:"snapshot_at" binding:"required"`
	Trails     []AwsCloudTrailTrail `json:"trails" binding:"dive"`
}

type AwsCloudTrailTrail struct {
	Name                     string `json:"name" binding:"required"`
	TrailArn                 string `json:"trail_arn" binding:"required"`
	HomeRegion               string `json:"home_region"`
	S3Bucket                 string `json:"s3_bucket"`
	IsMultiRegion            *bool  `json:"is_multi_region"`
	IncludeGlobalEvents      *bool  `json:"include_global_events"`
	KmsKeyID                 string `json:"kms_key_id"`
	LogFileValidationEnabled *bool  `json:"log_file_validation_enabled"`
	IsLogging                *bool  `json:"is_logging"`
}