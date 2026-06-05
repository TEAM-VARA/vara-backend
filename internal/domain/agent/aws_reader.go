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