package service

import (
	"strings"
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

// ── evidenceAttributionsFromFiles ──

func TestEvidenceAttributionsFromFiles_Empty(t *testing.T) {
	out := evidenceAttributionsFromFiles(nil)
	if len(out) != 0 {
		t.Errorf("len = %d, want 0", len(out))
	}
}

func TestEvidenceAttributionsFromFiles_WithK8s(t *testing.T) {
	files := []grc.EvidenceFile{
		{
			Filename: "pod.yaml",
			K8sSource: grc.K8sSource{
				ClusterName:  "prod",
				Namespace:    "ns1",
				ResourceKind: "Pod",
				ResourceName: "web-1",
			},
		},
		{
			Filename:  "policy.pdf",
			K8sSource: grc.K8sSource{},
		},
	}
	out := evidenceAttributionsFromFiles(files)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].Filename != "pod.yaml" {
		t.Errorf("out[0].Filename = %q", out[0].Filename)
	}
	if out[0].K8sSource.ClusterName != "prod" {
		t.Errorf("out[0].K8sSource.ClusterName = %q", out[0].K8sSource.ClusterName)
	}
	if out[1].Filename != "policy.pdf" {
		t.Errorf("out[1].Filename = %q", out[1].Filename)
	}
	if out[1].K8sSource.HasAny() {
		t.Error("out[1] should have no K8s source")
	}
}

// ── formatOneEvidenceSource edge cases ──

func TestFormatOneEvidenceSource_ClusterOnly(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "x.yaml",
		K8sSource: grc.K8sSource{ClusterName: "eks-prod"},
	})
	if s != "클러스터 eks-prod" {
		t.Errorf("got %q", s)
	}
}

func TestFormatOneEvidenceSource_NamespaceOnly(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "x.yaml",
		K8sSource: grc.K8sSource{Namespace: "kube-system"},
	})
	if s != "네임스페이스 kube-system" {
		t.Errorf("got %q", s)
	}
}

func TestFormatOneEvidenceSource_ResourceKindOnly(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "x.yaml",
		K8sSource: grc.K8sSource{ResourceKind: "Service"},
	})
	if s != "Service" {
		t.Errorf("got %q", s)
	}
}

func TestFormatOneEvidenceSource_ResourceNameOnly(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "x.yaml",
		K8sSource: grc.K8sSource{ResourceName: "my-svc"},
	})
	if s != "my-svc" {
		t.Errorf("got %q", s)
	}
}

func TestFormatOneEvidenceSource_KindAndName(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "x.yaml",
		K8sSource: grc.K8sSource{ResourceKind: "Deployment", ResourceName: "api-deploy"},
	})
	if s != "Deployment/api-deploy" {
		t.Errorf("got %q", s)
	}
}

func TestFormatOneEvidenceSource_ContainerOnly(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "x.yaml",
		K8sSource: grc.K8sSource{ContainerName: "sidecar"},
	})
	if s != "컨테이너 sidecar" {
		t.Errorf("got %q", s)
	}
}

func TestFormatOneEvidenceSource_NoK8s_FallbackToFilename(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename:  "policy.pdf",
		K8sSource: grc.K8sSource{},
	})
	if s != "policy.pdf" {
		t.Errorf("got %q, want filename fallback", s)
	}
}

func TestFormatOneEvidenceSource_FullContext(t *testing.T) {
	s := formatOneEvidenceSource(grc.EvidenceAttribution{
		Filename: "deploy.yaml",
		K8sSource: grc.K8sSource{
			ClusterName:   "prod-eks",
			Namespace:     "payment",
			ResourceKind:  "Deployment",
			ResourceName:  "payment-api",
			ContainerName: "api",
		},
	})
	expected := "클러스터 prod-eks / 네임스페이스 payment / Deployment/payment-api / 컨테이너 api"
	if s != expected {
		t.Errorf("got %q, want %q", s, expected)
	}
}

// ── formatEvidenceSourcesForRecommendation extended ──

func TestFormatEvidenceSourcesForRecommendation_MultipleSources(t *testing.T) {
	srcs := []grc.EvidenceAttribution{
		{
			Filename: "a.yaml",
			K8sSource: grc.K8sSource{
				ClusterName: "c1", Namespace: "ns1", ResourceKind: "Pod", ResourceName: "web",
			},
		},
		{
			Filename: "b.yaml",
			K8sSource: grc.K8sSource{
				ClusterName: "c1", Namespace: "ns2", ResourceKind: "Service", ResourceName: "api",
			},
		},
	}
	s := formatEvidenceSourcesForRecommendation(srcs)
	if s == "" {
		t.Fatal("expected non-empty")
	}
	if !strings.Contains(s, " · ") {
		t.Errorf("expected separator ' · ', got %q", s)
	}
	if !strings.Contains(s, "Pod/web") {
		t.Errorf("missing Pod/web in %q", s)
	}
	if !strings.Contains(s, "Service/api") {
		t.Errorf("missing Service/api in %q", s)
	}
}

func TestFormatEvidenceSourcesForRecommendation_MixedK8sAndNon(t *testing.T) {
	srcs := []grc.EvidenceAttribution{
		{Filename: "policy.pdf", K8sSource: grc.K8sSource{}}, // no K8s
		{
			Filename:  "pod.yaml",
			K8sSource: grc.K8sSource{Namespace: "prod", ResourceKind: "Pod", ResourceName: "x"},
		},
	}
	s := formatEvidenceSourcesForRecommendation(srcs)
	if s == "" {
		t.Fatal("expected non-empty (at least one source has K8s)")
	}
	// Should include the filename fallback for the non-K8s source
	if !strings.Contains(s, "policy.pdf") {
		t.Errorf("expected filename fallback for non-K8s source, got %q", s)
	}
	if !strings.Contains(s, "Pod/x") {
		t.Errorf("expected Pod/x, got %q", s)
	}
}

func TestFormatEvidenceSourcesForRecommendation_AllNonK8s(t *testing.T) {
	srcs := []grc.EvidenceAttribution{
		{Filename: "a.pdf"},
		{Filename: "b.json"},
	}
	s := formatEvidenceSourcesForRecommendation(srcs)
	if s != "" {
		t.Errorf("expected empty when no K8s sources, got %q", s)
	}
}

// ── generateRecommendations integration with K8s ──

func TestGenerateRecommendations_MultipleK8sSources(t *testing.T) {
	results := []grc.RuleResult{
		{
			RuleID:  "R005",
			Verdict: "미준수",
			Violations: []grc.Violation{
				{Description: "패스워드 길이 미달", Severity: "high"},
			},
			EvidenceSources: []grc.EvidenceAttribution{
				{
					Filename: "deploy-a.yaml",
					K8sSource: grc.K8sSource{
						ClusterName: "prod", Namespace: "ns-a", ResourceKind: "Deployment", ResourceName: "svc-a",
					},
				},
				{
					Filename: "deploy-b.yaml",
					K8sSource: grc.K8sSource{
						ClusterName: "prod", Namespace: "ns-b", ResourceKind: "Deployment", ResourceName: "svc-b",
					},
				},
			},
		},
	}
	ruleset := &Ruleset{
		Rules:     []Rule{{RuleID: "R005", Name: "비밀번호 정책 점검"}},
		LegalRefs: []LegalReference{{Law: "개인정보의 안전성 확보조치 기준", Article: "제5조"}},
	}
	recs := generateRecommendations(results, ruleset)
	if len(recs) != 1 {
		t.Fatalf("len = %d", len(recs))
	}
	if !strings.Contains(recs[0].Action, "Kubernetes") {
		t.Errorf("missing Kubernetes prefix: %s", recs[0].Action)
	}
	if !strings.Contains(recs[0].Action, "Deployment/svc-a") {
		t.Errorf("missing svc-a: %s", recs[0].Action)
	}
	if !strings.Contains(recs[0].Action, "Deployment/svc-b") {
		t.Errorf("missing svc-b: %s", recs[0].Action)
	}
}

func TestGenerateRecommendations_NoK8sNoPrefix(t *testing.T) {
	results := []grc.RuleResult{
		{
			RuleID:  "R005",
			Verdict: "미준수",
			Violations: []grc.Violation{
				{Description: "패스워드 길이 미달", Severity: "high"},
			},
			EvidenceSources: []grc.EvidenceAttribution{
				{Filename: "iam_policy.json"}, // no K8s source
			},
		},
	}
	ruleset := &Ruleset{
		Rules:     []Rule{{RuleID: "R005", Name: "비밀번호 정책 점검"}},
		LegalRefs: []LegalReference{{Law: "법", Article: "조"}},
	}
	recs := generateRecommendations(results, ruleset)
	if len(recs) != 1 {
		t.Fatalf("len = %d", len(recs))
	}
	if strings.Contains(recs[0].Action, "Kubernetes") {
		t.Errorf("should NOT have Kubernetes prefix when no K8s source: %s", recs[0].Action)
	}
	if !strings.HasPrefix(recs[0].Action, "개선 필요:") {
		t.Errorf("expected '개선 필요:' prefix, got: %s", recs[0].Action)
	}
}
