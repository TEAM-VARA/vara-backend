#!/bin/bash
# 사용법: ./scan-pod.sh <namespace> <pod_name>
# 예: ./scan-pod.sh default old-nginx
#
# 변경: cluster-reader/pods는 Cluster Agent v2가 사용 → pod-events로 분리

set -euo pipefail

BACKEND="${BACKEND:-http://10.0.14.69:8080}"
NAMESPACE="${1:?사용법: $0 <namespace> <pod_name>}"
POD_NAME="${2:?사용법: $0 <namespace> <pod_name>}"

echo "📦 [1/4] kubectl로 Pod 정보 추출"
POD_JSON=$(kubectl get pod -n "$NAMESPACE" "$POD_NAME" -o json)

POD_UID=$(echo "$POD_JSON" | jq -r '.metadata.uid')
NODE_NAME=$(echo "$POD_JSON" | jq -r '.spec.nodeName')
POD_IP=$(echo "$POD_JSON" | jq -r '.status.podIP // "0.0.0.0"')
IMAGE=$(echo "$POD_JSON" | jq -r '.status.containerStatuses[0].image')
IMAGE_ID=$(echo "$POD_JSON" | jq -r '.status.containerStatuses[0].imageID')
DIGEST=$(echo "$IMAGE_ID" | sed 's|.*@||')

if [[ -z "$DIGEST" || "$DIGEST" != sha256:* ]]; then
    DIGEST="sha256:$(echo -n "$IMAGE" | sha256sum | cut -d' ' -f1)"
    echo "⚠️ 실제 digest 없음. 가짜 사용: $DIGEST"
fi

echo "   Pod: $POD_NAME (uid=$POD_UID)"
echo "   Image: $IMAGE"
echo "   Digest: $DIGEST"

echo ""
echo "📦 [2/4] Trivy 이미지 스캔 (1~2분)"
SCAN_FILE=$(mktemp)
trivy image -f json -o "$SCAN_FILE" \
    --severity CRITICAL,HIGH,MEDIUM \
    --quiet "$IMAGE"

CVE_COUNT=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$SCAN_FILE")
echo "   발견된 CVE: $CVE_COUNT 개"

echo ""
echo "📤 [3/4] 백엔드에 SBOM 등록"
SBOM_PAYLOAD=$(jq -c \
    --arg image "$IMAGE" \
    --arg digest "$DIGEST" '{
        image: $image,
        image_digest: $digest,
        cves: [
            .Results[]?.Vulnerabilities[]? | {
                cve_id: .VulnerabilityID,
                severity: .Severity,
                cvss_score: ((.CVSS // {} | (.nvd.V3Score // .redhat.V3Score // 0))),
                package_name: .PkgName,
                installed_version: .InstalledVersion,
                fixed_version: (.FixedVersion // "")
            }
        ] | unique_by(.cve_id)
    }' "$SCAN_FILE")

curl -sS -X POST "$BACKEND/api/v1/agents/sbom" \
    -H "Content-Type: application/json" \
    -d "$SBOM_PAYLOAD" | jq .

echo ""
echo "📤 [3.5/4] 백엔드에 Pod 등록 (라우트: cluster-reader/pod-events)"
POD_PAYLOAD=$(jq -n \
    --arg uid "$POD_UID" --arg name "$POD_NAME" \
    --arg ns "$NAMESPACE" --arg node "$NODE_NAME" \
    --arg ip "$POD_IP" --arg image "$IMAGE" --arg digest "$DIGEST" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
        events: [{
            event_type: "pod_added",
            pod_uid: $uid,
            pod_name: $name,
            namespace: $ns,
            node_name: $node,
            ip: $ip,
            image: $image,
            image_digest: $digest,
            timestamp: $ts
        }]
    }')

curl -sS -X POST "$BACKEND/api/v1/agents/cluster-reader/pod-events" \
    -H "Content-Type: application/json" \
    -d "$POD_PAYLOAD" | jq .

echo ""
echo "📊 [4/4] Risk Scoring 호출 (외부 API 첫 호출은 30~60초)"
RISK_PAYLOAD=$(jq -n \
    --arg image "$IMAGE" --arg digest "$DIGEST" '{
        image_name: $image,
        image_digest: $digest
    }')

curl -sS -X POST "$BACKEND/api/v1/pods/$POD_UID/risk" \
    -H "Content-Type: application/json" \
    -d "$RISK_PAYLOAD" | jq .

echo ""
echo "✅ 완료. POD_UID: $POD_UID"
echo "   상세 조회: curl $BACKEND/api/v1/pods/$POD_UID/risk/details | jq ."
echo "   DBeaver: SELECT * FROM risk_scoring_results WHERE pod_id = '$POD_UID';"

rm "$SCAN_FILE"
