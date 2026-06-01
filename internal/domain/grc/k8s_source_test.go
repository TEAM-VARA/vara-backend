package grc

import (
	"encoding/json"
	"testing"
)

// ── K8sSource.HasAny ──

func TestK8sSource_HasAny_AllEmpty(t *testing.T) {
	k := K8sSource{}
	if k.HasAny() {
		t.Error("empty K8sSource should return false")
	}
}

func TestK8sSource_HasAny_SingleFields(t *testing.T) {
	cases := []struct {
		name string
		src  K8sSource
	}{
		{"cluster only", K8sSource{ClusterName: "prod"}},
		{"namespace only", K8sSource{Namespace: "default"}},
		{"kind only", K8sSource{ResourceKind: "Pod"}},
		{"name only", K8sSource{ResourceName: "web-abc"}},
		{"container only", K8sSource{ContainerName: "app"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.src.HasAny() {
				t.Error("expected HasAny() == true")
			}
		})
	}
}

func TestK8sSource_HasAny_AllFilled(t *testing.T) {
	k := K8sSource{
		ClusterName:   "prod-eks",
		Namespace:     "payments",
		ResourceKind:  "Pod",
		ResourceName:  "api-7f9cc",
		ContainerName: "app",
	}
	if !k.HasAny() {
		t.Error("fully filled K8sSource should return true")
	}
}

// ── K8sSource JSON serialization ──

func TestK8sSource_JSONOmitEmpty(t *testing.T) {
	k := K8sSource{ClusterName: "prod"}
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if _, ok := m["namespace"]; ok {
		t.Error("empty namespace should be omitted from JSON")
	}
	if m["cluster_name"] != "prod" {
		t.Errorf("cluster_name = %v, want prod", m["cluster_name"])
	}
}

func TestK8sSource_JSONRoundTrip(t *testing.T) {
	orig := K8sSource{
		ClusterName:   "eks-01",
		Namespace:     "kube-system",
		ResourceKind:  "Deployment",
		ResourceName:  "coredns",
		ContainerName: "coredns",
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var decoded K8sSource
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != orig {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

// ── EvidenceAttribution JSON ──

func TestEvidenceAttribution_JSONWithK8s(t *testing.T) {
	ea := EvidenceAttribution{
		Filename: "pod.yaml",
		K8sSource: K8sSource{
			ClusterName:  "prod",
			Namespace:    "default",
			ResourceKind: "Pod",
			ResourceName: "web-1",
		},
	}
	b, err := json.Marshal(ea)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["filename"] != "pod.yaml" {
		t.Errorf("filename = %v", m["filename"])
	}
	k8s, ok := m["k8s_source"].(map[string]any)
	if !ok {
		t.Fatal("k8s_source missing")
	}
	if k8s["resource_kind"] != "Pod" {
		t.Errorf("resource_kind = %v", k8s["resource_kind"])
	}
}

func TestEvidenceAttribution_JSONWithoutK8s(t *testing.T) {
	ea := EvidenceAttribution{Filename: "policy.pdf"}
	b, err := json.Marshal(ea)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["filename"] != "policy.pdf" {
		t.Errorf("filename = %v", m["filename"])
	}
	// k8s_source should be omitted when empty
	if _, ok := m["k8s_source"]; ok {
		k8s := m["k8s_source"].(map[string]any)
		if len(k8s) > 0 {
			t.Error("empty K8sSource should be omitted or empty in JSON")
		}
	}
}

// ── EvidenceMetadata with K8sSource ──

func TestEvidenceMetadata_JSONParse(t *testing.T) {
	raw := `{
		"filename": "deployment.yaml",
		"evidence_type": "정책_시스템_설정",
		"system": "Kubernetes",
		"description": "K8s deployment config",
		"target_rule_ids": ["2.5.4-R005"],
		"k8s_source": {
			"cluster_name": "prod-eks",
			"namespace": "payment",
			"resource_kind": "Deployment",
			"resource_name": "payment-api",
			"container_name": "api"
		}
	}`
	var meta EvidenceMetadata
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if meta.Filename != "deployment.yaml" {
		t.Errorf("filename = %q", meta.Filename)
	}
	if meta.K8sSource.ClusterName != "prod-eks" {
		t.Errorf("cluster = %q", meta.K8sSource.ClusterName)
	}
	if meta.K8sSource.ResourceKind != "Deployment" {
		t.Errorf("kind = %q", meta.K8sSource.ResourceKind)
	}
	if !meta.K8sSource.HasAny() {
		t.Error("HasAny should be true")
	}
}

func TestEvidenceMetadata_JSONParse_NoK8s(t *testing.T) {
	raw := `{
		"filename": "policy.pdf",
		"evidence_type": "정책_문서_존재"
	}`
	var meta EvidenceMetadata
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if meta.K8sSource.HasAny() {
		t.Error("HasAny should be false when k8s_source not provided")
	}
}

// ── CloudEnvironment ──

func TestCloudEnvironment_JSONSerialize(t *testing.T) {
	env := CloudEnvironment{
		ID:           1,
		CompanyID:    "acme",
		ResourceType: "pod",
		ResourceName: "web-abc",
		Namespace:    "production",
		ClusterName:  "eks-prod",
		RawData:      map[string]any{"kind": "Pod", "apiVersion": "v1"},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["company_id"] != "acme" {
		t.Errorf("company_id = %v", m["company_id"])
	}
	if m["resource_type"] != "pod" {
		t.Errorf("resource_type = %v", m["resource_type"])
	}
	raw, ok := m["raw_data"].(map[string]any)
	if !ok {
		t.Fatal("raw_data missing")
	}
	if raw["kind"] != "Pod" {
		t.Errorf("raw_data.kind = %v", raw["kind"])
	}
}

func TestCloudEnvironment_EmbeddingNotInJSON(t *testing.T) {
	env := CloudEnvironment{
		ID:           1,
		CompanyID:    "test",
		ResourceType: "service",
		ResourceName: "api",
		RawData:      map[string]any{},
		Embedding:    []float32{0.1, 0.2, 0.3},
	}
	b, _ := json.Marshal(env)
	var m map[string]any
	json.Unmarshal(b, &m)
	if _, ok := m["embedding"]; ok {
		t.Error("embedding should not appear in JSON (json:\"-\")")
	}
}

// ── RuleResult with EvidenceSources ──

func TestRuleResult_EvidenceSourcesJSON(t *testing.T) {
	rr := RuleResult{
		RuleID:  "R005",
		Verdict: "미준수",
		EvidenceSources: []EvidenceAttribution{
			{Filename: "a.yaml", K8sSource: K8sSource{Namespace: "ns1", ResourceKind: "Pod", ResourceName: "web"}},
			{Filename: "b.json"},
		},
	}
	b, err := json.Marshal(rr)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	srcs, ok := m["evidence_sources"].([]any)
	if !ok {
		t.Fatal("evidence_sources missing in JSON")
	}
	if len(srcs) != 2 {
		t.Fatalf("evidence_sources len = %d, want 2", len(srcs))
	}
}

func TestRuleResult_EvidenceSourcesOmittedWhenEmpty(t *testing.T) {
	rr := RuleResult{
		RuleID:  "R001",
		Verdict: "준수",
	}
	b, _ := json.Marshal(rr)
	var m map[string]any
	json.Unmarshal(b, &m)
	if _, ok := m["evidence_sources"]; ok {
		t.Error("evidence_sources should be omitted when nil/empty")
	}
}
