package main

// VARA Collector.
// AWS EKS 클러스터에서 자산/취약점/노출도를 수집해 VARA API로 푸시한 뒤,
// Evidence 생성까지 트리거한다. K8s CronJob 으로 주기 실행하는 것을 가정한다.
//
// 단계:
//   Phase 1) k8s Pod 목록 → /api/v1/assets
//   Phase 2) k8s Service(LoadBalancer/NodePort) + Ingress → /api/v1/exposures
//   Phase 3) AWS RDS → /api/v1/assets + /api/v1/exposures (PubliclyAccessible 한정)
//   Phase 4) 각 Pod 이미지에 Trivy 실행 → /api/v1/vulnerabilities
//   Phase 5) 모든 자산에 대해 /api/v1/evidence/generate 호출

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	apiBase := flag.String("api", envOr("VARA_API_BASE", "http://vara-api:8080"), "VARA API base URL")
	cluster := flag.String("cluster", envOr("CLUSTER_NAME", "default"), "cluster name (used in asset_id)")
	cloud := flag.String("cloud", envOr("CLOUD_PROVIDER", "aws"), "cloud provider")
	namespace := flag.String("namespace", os.Getenv("TARGET_NAMESPACE"), "target namespace (empty = all)")
	awsRegion := flag.String("aws-region", envOr("AWS_REGION", "ap-northeast-2"), "AWS region for RDS discovery")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig path (fallback when not in-cluster)")
	trivyBin := flag.String("trivy-bin", envOr("TRIVY_BIN", "trivy"), "trivy binary path")
	skipTrivy := flag.Bool("skip-trivy", envBool("SKIP_TRIVY", false), "skip image vulnerability scanning")
	skipAWS := flag.Bool("skip-aws", envBool("SKIP_AWS", false), "skip AWS RDS discovery")
	skipEvidence := flag.Bool("skip-evidence", envBool("SKIP_EVIDENCE", false), "skip /evidence/generate calls")
	flag.Parse()

	ctx := context.Background()
	api := NewAPIClient(*apiBase)

	if err := api.WaitReady(ctx, 90*time.Second); err != nil {
		log.Fatalf("vara-api not ready: %v", err)
	}
	log.Printf("vara-api reachable at %s", *apiBase)

	allAssetIDs := []string{}

	// ---- Phase 1: k8s assets ----
	k8sCol, err := NewK8sCollector(*cluster, *cloud, *namespace, *kubeconfig)
	if err != nil {
		log.Fatalf("k8s init: %v", err)
	}
	pods, err := k8sCol.CollectAssets(ctx)
	if err != nil {
		log.Fatalf("k8s collect assets: %v", err)
	}
	log.Printf("[phase1] discovered %d pods", len(pods))
	for _, a := range pods {
		if err := api.PostAsset(ctx, a); err != nil {
			log.Printf("[FAIL] asset %s: %v", a.AssetID, err)
			continue
		}
		allAssetIDs = append(allAssetIDs, a.AssetID)
	}

	// ---- Phase 2: k8s exposures ----
	k8sExp, err := k8sCol.CollectExposures(ctx)
	if err != nil {
		log.Printf("[WARN] k8s exposures: %v", err)
	} else {
		log.Printf("[phase2] discovered %d k8s exposures", len(k8sExp))
		for _, e := range k8sExp {
			if err := api.PostExposure(ctx, e); err != nil {
				log.Printf("[FAIL] exposure %s: %v", e.AssetID, err)
			}
		}
	}

	// ---- Phase 3: AWS RDS ----
	if !*skipAWS {
		awsCol, err := NewAWSCollector(ctx, *awsRegion, *cluster)
		if err != nil {
			log.Printf("[WARN] aws init: %v — skipping RDS discovery", err)
		} else {
			rdsAssets, rdsExps, err := awsCol.CollectRDS(ctx)
			if err != nil {
				log.Printf("[WARN] aws rds: %v", err)
			} else {
				log.Printf("[phase3] discovered %d RDS instances (%d public)", len(rdsAssets), len(rdsExps))
				for _, a := range rdsAssets {
					if err := api.PostAsset(ctx, a); err != nil {
						log.Printf("[FAIL] rds asset %s: %v", a.AssetID, err)
						continue
					}
					allAssetIDs = append(allAssetIDs, a.AssetID)
				}
				for _, e := range rdsExps {
					if err := api.PostExposure(ctx, e); err != nil {
						log.Printf("[FAIL] rds exposure %s: %v", e.AssetID, err)
					}
				}
			}
		}
	}

	// ---- Phase 4: Trivy image scan → vulnerabilities ----
	if !*skipTrivy {
		trivy := NewTrivyRunner(*trivyBin)
		scanned := 0
		for _, a := range pods {
			if a.Image == "" {
				continue
			}
			vulns, err := trivy.ScanImage(ctx, a.Image)
			if err != nil {
				log.Printf("[FAIL] trivy %s: %v", a.Image, err)
				continue
			}
			if err := api.PostVulnerabilities(ctx, a.AssetID, a.Image, vulns); err != nil {
				log.Printf("[FAIL] vulns %s: %v", a.AssetID, err)
				continue
			}
			scanned++
			log.Printf("[phase4] %s image=%s vulns=%d", a.AssetID, a.Image, len(vulns))
		}
		log.Printf("[phase4] scanned %d / %d pods", scanned, len(pods))
	}

	// ---- Phase 5: evidence generation ----
	if !*skipEvidence {
		generated := 0
		for _, id := range allAssetIDs {
			if err := api.GenerateEvidence(ctx, id); err != nil {
				log.Printf("[FAIL] evidence %s: %v", id, err)
				continue
			}
			generated++
		}
		log.Printf("[phase5] evidence generated for %d / %d assets", generated, len(allAssetIDs))
	}

	log.Println("collector run completed")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	return def
}
