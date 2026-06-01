package service

import (
	"strings"

	"github.com/vara/backend/internal/domain/grc"
)

func evidenceAttributionsFromFiles(files []grc.EvidenceFile) []grc.EvidenceAttribution {
	out := make([]grc.EvidenceAttribution, 0, len(files))
	for _, ef := range files {
		out = append(out, grc.EvidenceAttribution{
			Filename:  ef.Filename,
			K8sSource: ef.K8sSource,
		})
	}
	return out
}

// formatEvidenceSourcesForRecommendation returns a short Korean prefix when any K8s context exists.
func formatEvidenceSourcesForRecommendation(srcs []grc.EvidenceAttribution) string {
	if len(srcs) == 0 {
		return ""
	}
	hasK8s := false
	for _, s := range srcs {
		if s.K8sSource.HasAny() {
			hasK8s = true
			break
		}
	}
	if !hasK8s {
		return ""
	}
	parts := make([]string, 0, len(srcs))
	for _, s := range srcs {
		parts = append(parts, formatOneEvidenceSource(s))
	}
	return strings.Join(parts, " · ")
}

func formatOneEvidenceSource(s grc.EvidenceAttribution) string {
	var b strings.Builder
	if s.K8sSource.ClusterName != "" {
		b.WriteString("클러스터 ")
		b.WriteString(s.K8sSource.ClusterName)
	}
	if s.K8sSource.Namespace != "" {
		if b.Len() > 0 {
			b.WriteString(" / ")
		}
		b.WriteString("네임스페이스 ")
		b.WriteString(s.K8sSource.Namespace)
	}
	if s.K8sSource.ResourceKind != "" || s.K8sSource.ResourceName != "" {
		if b.Len() > 0 {
			b.WriteString(" / ")
		}
		if s.K8sSource.ResourceKind != "" && s.K8sSource.ResourceName != "" {
			b.WriteString(s.K8sSource.ResourceKind)
			b.WriteString("/")
			b.WriteString(s.K8sSource.ResourceName)
		} else if s.K8sSource.ResourceName != "" {
			b.WriteString(s.K8sSource.ResourceName)
		} else {
			b.WriteString(s.K8sSource.ResourceKind)
		}
	}
	if s.K8sSource.ContainerName != "" {
		if b.Len() > 0 {
			b.WriteString(" / ")
		}
		b.WriteString("컨테이너 ")
		b.WriteString(s.K8sSource.ContainerName)
	}
	if b.Len() == 0 {
		return s.Filename
	}
	return b.String()
}
