package service

import (
	"strings"
	"testing"

	"github.com/vara/backend/internal/domain/grc"
)

func TestFormatEvidenceSourcesForRecommendation(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if s := formatEvidenceSourcesForRecommendation(nil); s != "" {
			t.Fatalf("got %q", s)
		}
	})
	t.Run("no k8s context", func(t *testing.T) {
		srcs := []grc.EvidenceAttribution{{Filename: "a.yaml", K8sSource: grc.K8sSource{}}}
		if s := formatEvidenceSourcesForRecommendation(srcs); s != "" {
			t.Fatalf("expected empty, got %q", s)
		}
	})
	t.Run("full pod line", func(t *testing.T) {
		srcs := []grc.EvidenceAttribution{{
			Filename: "pod.yaml",
			K8sSource: grc.K8sSource{
				ClusterName: "prod-eks", Namespace: "payments", ResourceKind: "Pod",
				ResourceName: "api-7f9cc", ContainerName: "app",
			},
		}}
		s := formatEvidenceSourcesForRecommendation(srcs)
		if s == "" {
			t.Fatal("expected non-empty")
		}
		if !strings.Contains(s, "클러스터 prod-eks") {
			t.Fatalf("got %q", s)
		}
		if !strings.Contains(s, "Pod/api-7f9cc") {
			t.Fatalf("got %q", s)
		}
		if !strings.Contains(s, "컨테이너 app") {
			t.Fatalf("got %q", s)
		}
	})
}
