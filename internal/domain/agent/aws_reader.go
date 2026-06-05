package agent

import "time"

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