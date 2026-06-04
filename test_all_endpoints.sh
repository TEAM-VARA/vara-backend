#!/bin/bash
# VARA GRC 전체 엔드포인트 테스트 스크립트
# EC2에서 실행: bash test_all_endpoints.sh 2>&1 | tee test_result.txt

HOST="http://localhost:8081/api/v1"
COMPANY="test-company"
CLUSTER="vara-eks-test"
POD_NAME="vara-cluster-agent-648d96f79b-rs5ds"
POD_NS="default"

echo "============================================"
echo "  VARA GRC API 전체 테스트"
echo "============================================"

# ── 0. Health Check ──
echo ""
echo "▶ [0] Health Check"
curl -s http://localhost:8081/healthz | jq .

# ── 1. 룰셋 목록 ──
echo ""
echo "▶ [1] 룰셋 목록 (GET /rulesets)"
curl -s "$HOST/rulesets" | jq .

# ── 2. 룰셋 상세 (2.5.2) ──
echo ""
echo "▶ [2] 룰셋 상세 (GET /rulesets/2.5.2)"
curl -s "$HOST/rulesets/2.5.2" | jq '{item_id: .item_id, item_name: .item_name, rules: [.rules[] | {rule_id, name, judgment_source, extraction_method: .extraction_method, judgment_logic: .judgment_logic.method}]}'

# ── 3. 지침서 업로드 ──
echo ""
echo "▶ [3] 지침서 업로드 (POST /compliance/guidelines)"
if [ -f evidence_samples/정보보호_및_개인정보보호_지침서.pdf ]; then
  GUIDELINE_RESP=$(curl -s -X POST "$HOST/compliance/guidelines" \
    -F "company_id=$COMPANY" \
    -F "file=@evidence_samples/정보보호_및_개인정보보호_지침서.pdf")
  echo "$GUIDELINE_RESP" | jq .
else
  echo "  [SKIP] evidence_samples/정보보호_및_개인정보보호_지침서.pdf 없음"
fi

# ── 4. 지침서 목록 ──
echo ""
echo "▶ [4] 지침서 목록 (GET /compliance/guidelines)"
curl -s "$HOST/compliance/guidelines?company_id=$COMPANY" | jq .

# ── 5. 지침 점검 생성 (GL 룰 — evidence 없이) ──
echo ""
echo "▶ [5] 지침 점검 생성 — 2.5.2 (POST /compliance/checks, evidence 없이)"
CHECK_RESP=$(curl -s -X POST "$HOST/compliance/checks" \
  -F "company_id=$COMPANY" \
  -F "isms_p_item_id=2.5.2")
echo "$CHECK_RESP" | jq .
CHECK_ID=$(echo "$CHECK_RESP" | jq -r '.check_id // empty')

if [ -n "$CHECK_ID" ]; then
  echo ""
  echo "  → check_id: $CHECK_ID"
  echo "  → 결과 대기 중 (최대 10분)..."

  for i in $(seq 1 60); do
    sleep 10
    STATUS_RESP=$(curl -s "$HOST/compliance/checks/$CHECK_ID")
    STATUS=$(echo "$STATUS_RESP" | jq -r '.status')
    echo "  [$((i*10))s] status=$STATUS"
    if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
      break
    fi
  done

  # ── 6. 지침 점검 결과 상세 ──
  echo ""
  echo "▶ [6] 지침 점검 결과 (GET /compliance/checks/$CHECK_ID)"
  curl -s "$HOST/compliance/checks/$CHECK_ID" | jq .

  # ── 6-1. 룰별 verdict만 요약 ──
  echo ""
  echo "▶ [6-1] 룰별 verdict 요약"
  curl -s "$HOST/compliance/checks/$CHECK_ID" | jq '{
    check_id,
    status,
    verdict,
    summary,
    rule_verdicts: [.rule_results[]? | {rule_id, verdict, matched_indicators: (.matched_indicators // [])[:2], violations: (.violations // [])[:1]}]
  }'
else
  echo "  [ERROR] check_id 없음"
fi

# ── 7. 점검 목록 ──
echo ""
echo "▶ [7] 점검 목록 (GET /compliance/checks)"
curl -s "$HOST/compliance/checks?company_id=$COMPANY&page_size=5" | jq .

# ── 8. 클러스터 평가 실행 (R-rules + F-rules) ──
echo ""
echo "▶ [8] 클러스터 평가 실행 (POST /compliance/cluster/evaluate)"
CLUSTER_RESP=$(curl -s -X POST "$HOST/compliance/cluster/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
  "company_id": "'"$COMPANY"'",
  "cluster_name": "'"$CLUSTER"'"
}')
echo "$CLUSTER_RESP" | jq '{
  total_items,
  compliant_items,
  non_compliant_items,
  needs_review_items,
  total_rules,
  total_pods,
  items: [.items[]? | {isms_p_item_id, item_name, verdict, passed, failed, needs_review, violated_asset_count: (.violated_assets // [] | length)}]
}'

# ── 9. 전체 항목 한눈에 (Overview — R+F+GL 통합) ──
echo ""
echo "▶ [9] 전체 항목 한눈에 (GET /compliance/overview)"
curl -s "$HOST/compliance/overview?company_id=$COMPANY" | jq '{
  total_items,
  compliant_items,
  non_compliant_items,
  needs_review_items,
  no_data_items,
  total_rules,
  total_pods,
  items: [.items[]? | {isms_p_item_id, item_name, verdict, note, passed, failed, needs_review, violated_pod_count: (.violated_assets // [] | length), violated_pods: [(.violated_assets // [])[:2][] | {name, namespace, rules: [.violated_rules[]? | {rule_id, fail_message, remediation}]}]}]
}'

# ── 10. 특정 항목 상세 (2.6.1 — 미준수 항목) ──
echo ""
echo "▶ [10] 특정 항목 상세 (GET /compliance/items/2.6.1)"
curl -s "$HOST/compliance/items/2.6.1?company_id=$COMPANY&cluster_name=$CLUSTER" | jq '{
  isms_p_item_id,
  isms_p_item_name,
  total_violated_assets,
  assets: [(.violated_assets // [])[:3][] | {kind, name, namespace, violated_rules: [.violated_rules[]? | .rule_id]}]
}'

# ── 11. Pod별 점검 결과 ──
echo ""
echo "▶ [11] Pod별 점검 결과 (GET /compliance/pods/$POD_NAME/compliance)"
curl -s "$HOST/compliance/pods/$POD_NAME/compliance?company_id=$COMPANY&cluster_name=$CLUSTER&namespace=$POD_NS" | jq .

# ── 12. Pod별 위반 상세 ──
echo ""
echo "▶ [12] Pod별 위반 상세 (GET /compliance/pods/$POD_NAME/violations)"
curl -s "$HOST/compliance/pods/$POD_NAME/violations?company_id=$COMPANY&cluster_name=$CLUSTER&namespace=$POD_NS" | jq .

# ── 12-1. Pod별 모든 정보 통합 조회 ──
echo ""
echo "▶ [12-1] Pod 전체 정보 (GET /compliance/pods/$POD_NAME/detail)"
curl -s "$HOST/compliance/pods/$POD_NAME/detail?company_id=$COMPANY&cluster_name=$CLUSTER&namespace=$POD_NS" | jq '{
  pod_name, pod_uid, namespace, cluster_name, node, pod_ip, phase,
  service_account, labels, host_network, started_at, first_seen_at, last_seen_at,
  compliance: (if .compliance then {summary: .compliance.summary, cluster_findings_count: (.compliance.cluster_findings // [] | length)} else null end),
  violations: (if .violations then {overall_verdict: .violations.overall_verdict, total_violated_items: .violations.total_violated_items, items: [.violations.violated_items[]? | {isms_p_item_id, isms_p_item_name, failed, failed_rules: [.failed_rules[]? | {rule_id, name, verdict}]}]} else null end)
}'

# ── 13. Findings 요약 (F-rule 결과) ──
echo ""
echo "▶ [13] Findings 요약 (GET /compliance/findings/summary)"
curl -s "$HOST/compliance/findings/summary?company_id=$COMPANY&cluster_name=$CLUSTER" | jq '{
  total_findings,
  matched_count,
  unmatched_count,
  by_verdict,
  finding_sample: [(.findings // [])[:5][] | {rule_id, isms_p_item_id, verdict, verdict_type, matched, observation: (.observation // "")[:80]}]
}'

# ── 14. 룰 카탈로그 ──
echo ""
echo "▶ [14] 룰 카탈로그 (GET /compliance/rulesets/catalog)"
curl -s "$HOST/compliance/rulesets/catalog" | jq '{
  total_rules: (.rules // [] | length),
  total_findings: (.findings // [] | length),
  rule_ids: [(.rules // [])[:5][] | .rule_id],
  finding_ids: [(.findings // [])[:5][] | .finding_id]
}'

echo ""
echo "============================================"
echo "  테스트 완료"
echo "============================================"
