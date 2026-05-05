package service

import (
	"context"
	"fmt"
	"sort"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/platform/epss"
	"github.com/vara/backend/internal/platform/exploitdb"
	"github.com/vara/backend/internal/platform/kev"
	"github.com/vara/backend/internal/platform/nvd"
)

// 가중치 (총합 100)
const (
	WeightCVSS    = 30.0 // CVSS × 3
	WeightEPSS    = 30.0 // EPSS × 30
	WeightKEV     = 20.0
	WeightExploit = 20.0
)

// 등급 임계값
const (
	ThresholdCritical = 90.0
	ThresholdWarning  = 70.0
)

// ScoringService : Risk Scoring 비즈니스 로직
type ScoringService struct {
	nvd       *nvd.Client
	epss      *epss.Client
	kev       *kev.Client
	exploitDB *exploitdb.Client
}

func NewScoringService(
	nvd *nvd.Client,
	epss *epss.Client,
	kev *kev.Client,
	exploitDB *exploitdb.Client,
) *ScoringService {
	return &ScoringService{
		nvd:       nvd,
		epss:      epss,
		kev:       kev,
		exploitDB: exploitDB,
	}
}

// ComputeForCVEs : CVE 리스트에 대해 점수 계산
func (s *ScoringService) ComputeForCVEs(ctx context.Context, cveIDs []string) (*scoring.Computation, error) {
	if len(cveIDs) == 0 {
		return &scoring.Computation{CVEList: []string{}}, nil
	}

	details := make([]scoring.CVEDetail, 0, len(cveIDs))
	cveScores := make(map[string]float64)

	for _, cveID := range cveIDs {
		detail, score, err := s.computeOne(ctx, cveID)
		if err != nil {
			fmt.Printf("warn: cve %s scoring failed: %v\n", cveID, err)
			continue
		}
		details = append(details, *detail)
		cveScores[cveID] = score
	}

	var topCVE string
	var topScore float64
	for cveID, sc := range cveScores {
		if sc > topScore {
			topScore = sc
			topCVE = cveID
		}
	}

	var topDetail *scoring.CVEDetail
	for i := range details {
		if details[i].CVEID == topCVE {
			topDetail = &details[i]
			break
		}
	}

	result := scoring.Result{
		FinalScore: roundTo2(topScore),
		RiskLevel:  classifyLevel(topScore),
		CVEList:    cveIDs,
		TopCVE:     topCVE,
	}

	if topDetail != nil {
		result.CVSS = topDetail.CVSS.Score
		result.EPSS = topDetail.EPSS.Score
		result.KEVListed = topDetail.KEV.Listed
		result.ExploitDB = topDetail.Exploit.HasExploit

		result.CVSSScore = roundTo2(topDetail.CVSS.Score * (WeightCVSS / 10.0))
		result.EPSSScore = roundTo2(topDetail.EPSS.Score * WeightEPSS)
		if result.KEVListed {
			result.KEVScore = WeightKEV
		}
		if result.ExploitDB {
			result.ExploitScore = WeightExploit
		}
	}

	sort.SliceStable(details, func(i, j int) bool {
		return cveScores[details[i].CVEID] > cveScores[details[j].CVEID]
	})

	return &scoring.Computation{
		Result:  result,
		Details: details,
		CVEList: cveIDs,
	}, nil
}

func (s *ScoringService) computeOne(ctx context.Context, cveID string) (*scoring.CVEDetail, float64, error) {
	detail := &scoring.CVEDetail{CVEID: cveID}

	// 1. CVSS (NVD)
	nvdInfo, err := s.nvd.FetchCVE(ctx, cveID)
	if err == nil && nvdInfo.Found {
		detail.Description = nvdInfo.Description
		detail.CVSS = scoring.CVSSDetail{
			Score:    nvdInfo.CVSSScore,
			Severity: nvdInfo.Severity,
			Vector:   nvdInfo.VectorString,
			Note:     fmt.Sprintf("CVSS %.1f (%s) — %s", nvdInfo.CVSSScore, nvdInfo.Severity, cvssNote(nvdInfo.CVSSScore)),
		}
	} else {
		detail.CVSS.Note = "CVSS 정보를 가져오지 못했습니다"
	}

	// 2. EPSS
	epssInfo, err := s.epss.FetchEPSS(ctx, cveID)
	if err == nil && epssInfo.Found {
		detail.EPSS = scoring.EPSSDetail{
			Score:      epssInfo.Score,
			Percentile: epssInfo.Percentile,
			Note: fmt.Sprintf("EPSS %.4f — 향후 30일 내 공격받을 확률 약 %.1f%% (상위 %.1f%%)",
				epssInfo.Score, epssInfo.Score*100, epssInfo.Percentile*100),
		}
	} else {
		detail.EPSS.Note = "EPSS 정보를 가져오지 못했습니다"
	}

	// 3. KEV
	kevEntry, err := s.kev.IsListed(ctx, cveID)
	if err == nil && kevEntry != nil {
		detail.KEV = scoring.KEVDetail{
			Listed:    true,
			DateAdded: kevEntry.DateAdded,
			DueDate:   kevEntry.DueDate,
			Note: fmt.Sprintf("CISA KEV 등재 (등재일: %s) — 실제 공격 사례가 보고된 취약점입니다",
				kevEntry.DateAdded),
		}
	} else {
		detail.KEV = scoring.KEVDetail{
			Listed: false,
			Note:   "KEV에 등재되지 않음 (실제 공격 사례 미보고)",
		}
	}

	// 4. ExploitDB
	hasExploit, urls, err := s.exploitDB.HasExploit(ctx, cveID)
	if err == nil && hasExploit {
		detail.Exploit = scoring.ExploitDetail{
			HasExploit:  true,
			ExploitURLs: urls,
			Note:        fmt.Sprintf("Exploit-DB에 공격 코드 %d개 등재 — 누구나 즉시 악용 가능", len(urls)),
		}
	} else {
		detail.Exploit = scoring.ExploitDetail{
			HasExploit: false,
			Note:       "Exploit-DB에 등재된 공격 코드 없음",
		}
	}

	score := 0.0
	score += detail.CVSS.Score * (WeightCVSS / 10.0)
	score += detail.EPSS.Score * WeightEPSS
	if detail.KEV.Listed {
		score += WeightKEV
	}
	if detail.Exploit.HasExploit {
		score += WeightExploit
	}

	return detail, score, nil
}

func classifyLevel(score float64) string {
	switch {
	case score >= ThresholdCritical:
		return "Critical"
	case score >= ThresholdWarning:
		return "Warning"
	default:
		return "Info"
	}
}

func cvssNote(score float64) string {
	switch {
	case score >= 9.0:
		return "원격 공격이 가능하며 인증 없이 시스템 장악 가능 수준"
	case score >= 7.0:
		return "심각한 영향을 초래할 수 있는 취약점"
	case score >= 4.0:
		return "중간 수준의 영향이 있는 취약점"
	default:
		return "낮은 수준의 취약점"
	}
}

func roundTo2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
