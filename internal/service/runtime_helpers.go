package service

import (
	"strings"

	"github.com/vara/backend/internal/repository/postgres"
)

// PodIPIndex — Pod IP로 Pod 정보 빠르게 찾기
type PodIPIndex map[string]PodIPEntry

type PodIPEntry struct {
	PodUID    string
	Name      string
	Namespace string
}

// BuildPodIPIndex — PodForAttackPath 목록에서 IP 인덱스 생성
// 의존: PodForAttackPath에 PodIP 필드 추가 필요 (가이드 참고)
func BuildPodIPIndex(pods []postgres.PodForAttackPath) PodIPIndex {
	idx := make(PodIPIndex, len(pods))
	for _, p := range pods {
		if p.PodIP == "" {
			continue
		}
		idx[p.PodIP] = PodIPEntry{
			PodUID:    p.PodUID,
			Name:      p.Name,
			Namespace: p.Namespace,
		}
	}
	return idx
}

// BuildPodIPIndexFromSnapshot — PodSnapshot 목록에서 IP 인덱스 생성
// 의존: PodSnapshot에 PodIP 필드 추가 필요
func BuildPodIPIndexFromSnapshot(pods []postgres.PodSnapshot) PodIPIndex {
	idx := make(PodIPIndex, len(pods))
	for _, p := range pods {
		if p.PodIP == "" {
			continue
		}
		idx[p.PodIP] = PodIPEntry{
			PodUID:    p.PodUID,
			Name:      p.Name,
			Namespace: p.Namespace,
		}
	}
	return idx
}

func (idx PodIPIndex) Get(ip string) (PodIPEntry, bool) {
	if ip == "" {
		return PodIPEntry{}, false
	}
	entry, ok := idx[ip]
	return entry, ok
}

// ParseSrcPodID — "namespace/name" → (namespace, name)
func ParseSrcPodID(srcPodID string) (namespace, name string) {
	if srcPodID == "" {
		return "", ""
	}
	idx := strings.Index(srcPodID, "/")
	if idx < 0 {
		return "", srcPodID
	}
	return srcPodID[:idx], srcPodID[idx+1:]
}

// PodKeyIndex — "namespace/name" → pod_uid 매핑
type PodKeyIndex map[string]string

func BuildPodKeyIndex(pods []postgres.PodForAttackPath) PodKeyIndex {
	idx := make(PodKeyIndex, len(pods))
	for _, p := range pods {
		idx[p.Namespace+"/"+p.Name] = p.PodUID
	}
	return idx
}

func BuildPodKeyIndexFromSnapshot(pods []postgres.PodSnapshot) PodKeyIndex {
	idx := make(PodKeyIndex, len(pods))
	for _, p := range pods {
		idx[p.Namespace+"/"+p.Name] = p.PodUID
	}
	return idx
}

func (idx PodKeyIndex) LookupByKey(srcPodID string) string {
	return idx[srcPodID]
}

func MakeSrcPodID(namespace, name string) string {
	return namespace + "/" + name
}

// MatchesExcludePattern — prefix 매칭
func MatchesExcludePattern(srcPodID string, patterns []string) bool {
	for _, prefix := range patterns {
		if strings.HasPrefix(srcPodID, prefix) {
			return true
		}
	}
	return false
}
