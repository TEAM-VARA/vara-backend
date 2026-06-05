# ISMS-P 룰셋 상세 설명서 (134룰 · 원본 147룰 중 K8s 범위 밖 R-2.5.4-03~15 13룰 제외)

각 룰은 ① 실제 룰 JSON, ② 무엇을 하는 룰인지, ③ 어떤 테이블·컬럼/지침 문장을 보는지, ④ 인증기준의 어느 부분을 확인하는지 순으로 정리.

룰 유형 표기:
- ⚙️ **클라우드 실측(K8s API)** — DB 스냅샷 테이블(`cluster_*`)의 적재값을 읽어 자동 판정
- 📄 **지침·정책 점검(RAG)** — 회사 지침서 문장과 요구 문장의 의미 동일성을 LLM이 판정(충족/미충족/확인불가)
- 🧑‍💻 **클라우드 수동 점검(F-룰)** — 자동 판정이 어려워 스냅샷을 사람이 검토하는 보조 점검

> ⚠️ namespace 라벨은 `cluster_namespaces`에 라벨 컬럼이 없어 현재 미적재 상태 — assembler가 빈 값으로 채우므로 namespace 라벨 기반 판정 룰은 현 구조상 항상 미준수로 떨어진다.

---

## 1.2.1 정보자산 식별

### F-1.2.1-01 · K8s 클러스터 자산 인벤토리
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-1.2.1-01",
  "name": "K8s 클러스터 자산 인벤토리",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Cluster",
    "required_data": ["cluster_namespaces", "cluster_pods", "cluster_services", "cluster_configmaps"],
    "condition": { "operator": "inventory_report" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "1.2.1", "match_strength": "supportive" }],
    "kisa_defect_case_refs": [{ "case_number": 4, "description": "외부 위탁 IT 서비스 자산 식별 누락", "match": "partial" }],
    "additional_review_items": ["이 K8s 자산 목록이 회사 자산관리대장에 포함되어 있는가", "K8s 외 자산(온프레미스, 외부 위탁 등)은 별도 식별되어 있는가"],
    "manual_check_areas": ["외부 위탁 자산 식별 절차", "자산관리시스템(CMDB)"],
    "automation_coverage": { "percentage": 30, "covered": "K8s 클러스터 내 자산 식별", "not_covered": "외부 자산, 분류 기준 합리성, 중요도 평가" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 클러스터 스냅샷을 모아 자산 인벤토리를 만든 뒤, 회사 자산관리대장 반영 여부 등은 사람이 검토하는 보조 점검. 준수/검토필요로 표시.
- **집계 대상 테이블** — `cluster_namespaces`, `cluster_pods`, `cluster_services`, `cluster_configmaps`
- **사람 검토 영역** — 외부 위탁 자산 식별 절차, 자산관리시스템(CMDB)
- **자동화 커버리지** — 30% (K8s 내 자산 식별만 자동, 외부 자산·분류 합리성·중요도 평가는 수동)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 외부 자산관리대장/CMDB에 K8s 자산 + 온프레미스·외부위탁 자산이 통합 등재되고 분류·중요도가 산정돼 최신으로 관리됨
- **인증기준의 어느 부분을 보는가** — 1.2.1 인증기준 "…관리체계 범위 내 **모든 정보자산을 식별·분류**하고…" 중 자산 식별의 완전성(K8s 외 자산 포함 여부)을 본다.
- ISMS-P 1.2.1 정보자산 식별 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.1-01 · namespace 자산 분류 라벨
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.1-01",
  "name": "namespace 자산 분류 라벨",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "namespace.metadata.labels.data-classification", "op": "in", "value": ["public", "internal", "confidential", "pii", "sensitive-pii"], "description": "데이터 분류 등급 라벨 존재" },
    { "field": "namespace.metadata.labels.isms-p/owner", "op": "!=", "value": null, "description": "자산 책임자 라벨 존재" },
    { "field": "namespace.metadata.labels.isms-p/criticality", "op": "in", "value": ["critical", "high", "medium", "low"], "description": "자산 중요도 라벨 존재" }
  ],
  "activates_on_pass": [
    { "condition": "data-classification == pii", "require": ["R-2.7.1-POD-01", "R-2.9.4-POD"], "note": "PII 등급 시 etcd 암호화 + 1년 이상 접속기록 필수" },
    { "condition": "data-classification == sensitive-pii", "require": ["R-2.9.4-POD"], "note": "민감 PII 시 2년 이상 접속기록 필수" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 },
  "verdict_type": "needs_review"
}
```

- namespace에 데이터 분류 등급·책임자·중요도 라벨이 모두 붙어 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_namespaces` / 컬럼: `namespace` (TEXT). ⚠️ **라벨 컬럼이 없어 namespace 라벨이 DB에 적재되지 않음** — assembler가 빈 값으로 채우므로 현 구조상 **무조건 미준수**.
- **JSON 필드 ↔ DB 매핑** — `namespace.metadata.labels.*` 에 대응하는 DB 라벨 컬럼이 부재. (구조 보완 전까지 라벨 기반 판정 불가)
- 판정 기준: `data-classification in [public·internal·confidential·pii·sensitive-pii]` AND `isms-p/owner != null` AND `isms-p/criticality in [critical·high·medium·low]` ⇒ 셋 다 충족 시 준수
- **인증기준의 어느 부분을 보는가** — 1.2.1 인증기준 중 **'분류기준에 따른 분류 + 중요도 산정'** 이 자산 단위(namespace)에 실제 적용됐는지를 라벨로 본다.
- ISMS-P 1.2.1 정보자산 식별 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.1-GL01 · 정보자산 분류기준 수립
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.1-GL01",
  "name": "정보자산 분류기준 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["관리체계 범위 내 모든 정보자산을 식별·분류하기 위한 분류기준을 수립한다."],
  "compliance_indicators": [{ "description": "조직의 업무특성에 따라 정보자산 분류기준을 수립하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "1.2.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '정보자산 분류기준 수립'이 규정돼 있는지 의미 기반(RAG)으로 판정한다.
- **점검 기준 문장(keywords)**: 「관리체계 범위 내 모든 정보자산을 식별·분류하기 위한 분류기준을 수립한다.」
- 판정: 의미가 같은 규정이 있으면 충족 / 없으면 미충족 / 문서를 못 찾으면 확인불가
- **인증기준의 어느 부분을 보는가** — 1.2.1 인증기준 "…**정보자산 분류기준을 수립하여**…" 중 **'분류기준 수립' 구절**. (중요도 산정→GL02, 목록 최신→GL03, 정책 버전·승인→GL04로 분담)
- ISMS-P 1.2.1 정보자산 식별 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.1-GL02 · 중요도 산정 및 보안등급 부여
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.1-GL02",
  "name": "중요도 산정 및 보안등급 부여",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["식별된 정보자산에 대하여 법적 요구사항 및 업무 영향도를 고려하여 중요도를 산정하고 보안등급을 부여한다."],
  "compliance_indicators": [{ "description": "정보자산의 중요도를 결정하고 보안등급을 부여하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "1.2.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '중요도 산정 및 보안등급 부여'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「식별된 정보자산에 대하여 법적 요구사항 및 업무 영향도를 고려하여 중요도를 산정하고 보안등급을 부여한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 1.2.1 인증기준 "…**중요도를 산정한 후**…" 중 **'중요도 산정·보안등급 부여' 구절**.
- ISMS-P 1.2.1 정보자산 식별 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.1-GL03 · 정보자산 목록 최신 유지
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.1-GL03",
  "name": "정보자산 목록 최신 유지",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정기적으로 정보자산 현황을 조사하여 정보자산 목록을 최신 상태로 유지한다."],
  "compliance_indicators": [{ "description": "정기적으로 정보자산 현황을 조사하여 목록을 최신으로 유지하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "1.2.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '정보자산 목록 최신 유지'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「정기적으로 정보자산 현황을 조사하여 정보자산 목록을 최신 상태로 유지한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 1.2.1 인증기준 "…그 **목록을 최신으로 관리**하여야 한다." 중 **'목록 최신 유지' 구절**.
- ISMS-P 1.2.1 정보자산 식별 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.1-GL04 · 분류기준 정책의 버전·승인·갱신 관리
📄 지침·정책 점검(RAG) · 🆕 구 R-1.2.1-02 문장 GL로 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.1-GL04",
  "name": "분류기준 정책의 버전·승인·갱신 관리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정보자산 분류기준 정책에는 버전·승인자·승인일자를 명시하고 최소 1년에 한 번 이상 갱신하도록 규정한다."],
  "compliance_indicators": [{ "description": "분류기준 정책에 버전·승인자·승인일자가 명시되고 정기적으로(연 1회 이상) 갱신하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "1.2.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '분류기준 정책의 버전·승인·갱신 관리'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「정보자산 분류기준 정책에는 버전·승인자·승인일자를 명시하고 최소 1년에 한 번 이상 갱신하도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 1.2.1 인증기준 "…정보자산 **분류기준을 수립하여**…목록을 **최신으로 관리**…" 의 운영 측면, 즉 분류기준 정책 자체의 버전·승인·정기 갱신 체계를 본다.
- ISMS-P 1.2.1 정보자산 식별 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

## 1.2.2 현황 및 흐름분석

### F-1.2.2-01 · 클러스터 내부 통신 관계 인벤토리
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-1.2.2-01",
  "name": "클러스터 내부 통신 관계 인벤토리",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Cluster",
    "required_data": ["cluster_services", "cluster_ingresses", "cluster_network_policies", "cluster_pods"],
    "condition": { "operator": "traffic_graph_report" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "1.2.2", "match_strength": "supportive" }],
    "additional_review_items": ["이 통신 관계가 회사 정보흐름도에 반영되어 있는가", "개인정보 처리 흐름이 별도 표시되어 있는가"],
    "manual_check_areas": ["개인정보 처리 시스템 흐름도"],
    "automation_coverage": { "percentage": 30, "covered": "K8s 통신 관계", "not_covered": "흐름도 문서 자체, K8s 외 시스템 연계" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 서비스·인그레스·네트워크정책·파드를 모아 클러스터 내부 통신 그래프를 만든 뒤, 정보흐름도 반영 여부는 사람이 검토.
- **집계 대상 테이블** — `cluster_services`, `cluster_ingresses`, `cluster_network_policies`, `cluster_pods`
- **사람 검토 영역** — 개인정보 처리 시스템 흐름도
- **자동화 커버리지** — 30% (K8s 통신 관계만 자동, 흐름도 문서·외부 연계는 수동)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 본 룰이 도출한 통신 관계가 정보서비스 흐름도 문서에 누락 없이 반영됨
  - 개인정보 처리 흐름이 개인정보 흐름도에 수집·보유·이용/제공·파기 단계로 표시됨
- **인증기준의 어느 부분을 보는가** — 1.2.2 인증기준 "…업무절차와 흐름을 파악하여 **정보서비스 흐름도, 개인정보 흐름도** 등을 작성…" 중 흐름 파악의 입력자료(통신 관계)가 흐름도에 반영됐는지를 본다.
- ISMS-P 1.2.2 현황 및 흐름분석 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### F-1.2.2-02 · 외부 의존성 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-1.2.2-02",
  "name": "외부 의존성 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Service + eBPF",
    "required_data": ["cluster_services", "ebpf_dns_queries"],
    "condition": { "operator": "external_dependency_report", "filter": { "type": "ExternalName" } },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "1.2.2", "match_strength": "supportive" }],
    "additional_review_items": ["발견된 외부 의존성이 모두 정보흐름도에 등록되어 있는가", "미등록 외부 연계 사유 확인", "외부 위탁 계약 현황 매칭"],
    "manual_check_areas": ["외부 위탁 계약서", "외부 연계 시스템 목록"],
    "automation_coverage": { "percentage": 50, "covered": "클러스터에서 보이는 외부 연결", "not_covered": "K8s 외 시스템의 외부 연결" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- ExternalName 서비스·DNS 쿼리로 외부 의존성을 찾아낸 뒤, 흐름도/계약 등록 여부는 사람이 검토.
- **집계 대상 테이블** — `cluster_services`, `ebpf_dns_queries`
- **사람 검토 영역** — 외부 위탁 계약서, 외부 연계 시스템 목록
- **자동화 커버리지** — 50% (클러스터에서 보이는 외부 연결만 자동)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 발견된 외부 연계가 정보흐름도에 모두 등록돼 있고 외부 위탁 계약/외부 연계 시스템 목록과 일치함
- **인증기준의 어느 부분을 보는가** — 1.2.2 인증기준 중 **외부 연계를 포함한 흐름의 완전성**(발견된 외부 의존성이 흐름도에 모두 등록됐는지)을 본다.
- ISMS-P 1.2.2 현황 및 흐름분석 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.2-01 · 외부 의존성 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.2-01",
  "name": "외부 의존성 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "externalname_service.metadata.labels.isms-p/external-dependency", "op": "!=", "value": null, "description": "ExternalName Service에 외부 의존성 분류 라벨 존재" },
    { "field": "externalname_service.metadata.labels.isms-p/data-flow-id", "op": "!=", "value": null, "description": "흐름도 매핑 ID 라벨 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- ExternalName 서비스에 외부 의존성 분류 라벨과 흐름도 매핑 ID 라벨이 붙어 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_services` / 컬럼: `type`, `external_name`은 적재됨. ⚠️ 그러나 **`labels`/`annotations` 컬럼이 스키마에 없어**(migrations/005) 이 룰이 보는 라벨은 DB에 적재되지 않음 — 현 구조상 **사실상 미준수**.
- **JSON 필드 ↔ DB 매핑** — `externalname_service.metadata.labels.isms-p/external-dependency`, `.../data-flow-id`에 대응하는 라벨 컬럼이 `cluster_services`에 부재. (라벨 컬럼 추가 전까지 판정 불가)
- 판정 기준: 두 라벨 모두 `!= null` ⇒ 준수 (단, 현재는 라벨 미적재로 충족 불가)
- **인증기준의 어느 부분을 보는가** — 1.2.2 인증기준 중 **외부 연계가 흐름도에 매핑·관리되는지**(라벨로 흐름도 ID가 연결돼 있는지)를 본다.
- ISMS-P 1.2.2 현황 및 흐름분석 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.2-02 · Ingress 흐름도 등록 annotation 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.2-02",
  "name": "Ingress 흐름도 등록 annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "ingress.metadata.annotations.isms-p/flow-diagram-registered", "op": "==", "value": "true", "description": "Ingress에 흐름도 등록 annotation 존재" },
    { "field": "ingress.metadata.annotations.isms-p/service-flow-id", "op": "!=", "value": null, "description": "정보서비스 흐름도 ID annotation 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Ingress에 흐름도 등록 annotation과 흐름도 ID annotation이 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_ingresses` / 컬럼: `ingress_class`, `rules`(JSONB), `tls`(JSONB) 및 annotation.
- **JSON 필드 ↔ DB 매핑** — `ingress.metadata.annotations.isms-p/flow-diagram-registered`(=="true"), `.../service-flow-id`(!=null).
- 판정 기준: 등록 annotation == "true" AND 흐름도 ID != null ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 1.2.2 인증기준 중 **외부 진입점(Ingress)이 정보서비스 흐름도에 등록·매핑됐는지**를 본다.
- ISMS-P 1.2.2 현황 및 흐름분석 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.2-GL01 · 정보서비스·개인정보 흐름도 작성
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.2-GL01",
  "name": "정보서비스·개인정보 흐름도 작성",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고 정보서비스 흐름도·개인정보 흐름도 등으로 문서화한다."],
  "compliance_indicators": [{ "description": "업무절차와 흐름을 파악하여 정보서비스 흐름도·개인정보 흐름도로 문서화하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "1.2.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '흐름도 작성·문서화'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고 정보서비스 흐름도·개인정보 흐름도 등으로 문서화한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 1.2.2 인증기준 "…**흐름도 등을 작성**하여야 한다." 중 **'흐름도 작성·문서화' 구절**. (최신성 유지는 GL02로 분담)
- ISMS-P 1.2.2 현황 및 흐름분석 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-1.2.2-GL02 · 흐름도 최신성 유지
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-1.2.2-GL02",
  "name": "흐름도 최신성 유지",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["서비스·업무·정보자산의 변화에 따라 업무절차 및 개인정보 흐름을 주기적으로 검토하여 흐름도 등 관련 문서의 최신성을 유지한다."],
  "compliance_indicators": [{ "description": "변화에 따라 흐름도 등 관련 문서를 주기적으로 검토·갱신하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "1.2.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '흐름도 최신성 유지'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「서비스·업무·정보자산의 변화에 따라 업무절차 및 개인정보 흐름을 주기적으로 검토하여 흐름도 등 관련 문서의 최신성을 유지한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 1.2.2 인증기준의 운영 측면, 즉 작성된 흐름도가 변화에 맞춰 **주기적으로 검토·갱신**되는지를 본다.
- ISMS-P 1.2.2 현황 및 흐름분석 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

## 2.1.3 정보자산 관리

### F-2.1.3-01 · Pod 책임자 정보 부재
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.1.3-01",
  "name": "Pod 책임자 정보 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "additional_evidence",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": ["cluster_pods.annotations", "cluster_pods.labels"],
    "condition": { "operator": "any_owner_indicator_exists", "fields": ["annotations.owner", "annotations.contact", "labels.team"] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.1.3", "match_strength": "indirect" }],
    "additional_review_items": ["회사가 K8s annotation으로 책임자를 관리하는 정책인가", "외부 자산관리시스템(CMDB)에서 책임자 매핑 여부", "책임자 미지정 자산의 사유 확인"],
    "manual_check_areas": ["자산관리시스템(CMDB) 책임자 매핑"],
    "automation_coverage": { "percentage": 30, "covered": "K8s 라벨 기반 책임자 식별", "not_covered": "외부 시스템 매핑, 책임 위임 절차" },
    "alternative_controls": ["외부 CMDB", "ITSM 시스템"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- Pod에 owner/contact/team 정보가 있는지 모은 뒤, CMDB 책임자 매핑 등은 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.annotations`(JSONB), `cluster_pods.labels`(JSONB)
- **사람 검토 영역** — 자산관리시스템(CMDB) 책임자 매핑
- **자동화 커버리지** — 30% (K8s 라벨 기반 책임자 식별만)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - K8s owner 라벨이 없어도 외부 CMDB/ITSM에 해당 워크로드의 책임자·소유팀이 매핑돼 있음
- **인증기준의 어느 부분을 보는가** — 2.1.3 인증기준의 취급절차 운영 전제인 **자산 책임자 식별**(책임 주체 부재 여부)을 본다.
- ISMS-P 2.1.3 정보자산 관리 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### F-2.1.3-02 · 자산 변경 활동 감지
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.1.3-02",
  "name": "자산 변경 활동 감지",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Workload (history)",
    "required_data": ["cluster_workloads (snapshot history)"],
    "condition": { "operator": "change_activity_report", "time_window": "7d" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.1.3", "match_strength": "supportive" }],
    "additional_review_items": ["이 변경 사항이 회사 자산관리 절차를 거쳤는가", "자산관리대장에 반영되었는가", "변경 신청/승인 결재 기록과 매칭"],
    "manual_check_areas": ["변경관리 시스템(ITSM)", "자산관리대장"],
    "automation_coverage": { "percentage": 100, "covered": "변경 감지", "not_covered": "변경 절차 준수 여부" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 최근 7일 워크로드 스냅샷 이력에서 변경을 감지한 뒤, 변경 절차 준수 여부는 사람이 검토.
- **집계 대상 테이블** — `cluster_workloads`(스냅샷 이력)
- **사람 검토 영역** — 변경관리 시스템(ITSM), 자산관리대장
- **자동화 커버리지** — 100% 변경 감지(단, 절차 준수 여부는 수동)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 감지된 변경이 변경관리(ITSM) 신청·승인 결재를 거쳤고 자산관리대장에 반영됨
- **인증기준의 어느 부분을 보는가** — 2.1.3 인증기준의 **취급(변경) 절차 준수**, 즉 감지된 변경이 정식 절차를 거쳤는지를 본다.
- ISMS-P 2.1.3 정보자산 관리 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.1.3-01 · 워크로드 owner annotation 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.1.3-01",
  "name": "워크로드 owner annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "workload.metadata.annotations.isms-p/owner", "op": "!=", "value": null, "description": "워크로드에 자산 책임자(owner) annotation 존재" },
    { "field": "workload.metadata.annotations.isms-p/owner-team", "op": "!=", "value": null, "description": "워크로드에 소유 팀(owner-team) annotation 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 워크로드에 책임자·소유팀 annotation이 모두 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `annotations` (JSONB)
- **JSON 필드 ↔ DB 매핑** — `workload.metadata.annotations.isms-p/owner`, `.../owner-team` = `cluster_pods.annotations ->> 'isms-p/owner'`, `->> 'isms-p/owner-team'`.
- 판정 기준: 두 annotation 모두 `!= null` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.1.3 인증기준의 취급 전제인 **자산 책임자 지정**이 워크로드 단위에 적용됐는지를 본다.
- ISMS-P 2.1.3 정보자산 관리 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.1.3-02 · security-class 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.1.3-02",
  "name": "security-class 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "workload.metadata.labels.security-class", "op": "in", "value": ["critical", "high", "medium", "low"], "description": "워크로드에 유효한 보안등급(security-class) 라벨 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 워크로드에 유효한 보안등급(security-class) 라벨이 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `labels` (JSONB)
- **JSON 필드 ↔ DB 매핑** — `workload.metadata.labels.security-class` = `cluster_pods.labels ->> 'security-class'`.
- 판정 기준: `security-class in [critical·high·medium·low]` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.1.3 인증기준 "…**보안등급**과 취급절차를 정하고…" 중 **보안등급 부여**가 워크로드에 반영됐는지를 본다.
- ISMS-P 2.1.3 정보자산 관리 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.1.3-GL01 · 보안등급별 취급절차·보호대책 정의
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.1.3-GL01",
  "name": "보안등급별 취급절차·보호대책 정의",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정보자산의 보안등급에 따른 취급절차 및 보호대책을 정의하고 이행한다."],
  "compliance_indicators": [{ "description": "보안등급에 따른 취급절차와 보호대책을 정의·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.1.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '보안등급별 취급절차·보호대책'이 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「정보자산의 보안등급에 따른 취급절차 및 보호대책을 정의하고 이행한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.1.3 인증기준 "…보안등급과 **취급절차를 정하고, 이에 따라 취급**…" 중 **'보안등급별 취급절차·보호대책 정의' 구절**.
- ISMS-P 2.1.3 정보자산 관리 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.1.3-GL02 · 자산 책임자·관리자 지정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.1.3-GL02",
  "name": "자산 책임자·관리자 지정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["식별된 정보자산에 대하여 책임자 및 관리자를 지정한다."],
  "compliance_indicators": [{ "description": "식별된 정보자산에 책임자 및 관리자를 지정하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.1.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '자산 책임자·관리자 지정'이 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「식별된 정보자산에 대하여 책임자 및 관리자를 지정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.1.3 인증기준의 취급 책임 주체, 즉 **자산별 책임자·관리자 지정** 규정 여부를 본다.
- ISMS-P 2.1.3 정보자산 관리 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

## 2.5.1 사용자 계정 관리

### F-2.5.1-01 · default ServiceAccount 사용 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.5.1-01",
  "name": "default ServiceAccount 사용 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": ["cluster_pods.service_account", "cluster_pods.namespace"],
    "condition": { "operator": "in_set", "field": "service_account", "values": ["", "default"] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.5.1", "match_strength": "direct" }, { "framework": "개인정보보호법", "item": "안전성 확보조치 - 계정 분리", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "공용 계정 사용", "match": "direct" }],
    "additional_review_items": ["해당 Pod가 인증범위 내 자산인가", "default SA 사용에 대한 회사 정책상 예외 허용 사례인가", "시스템 namespace는 예외 처리"],
    "manual_check_areas": ["공용 계정 사용 예외 승인 기록"],
    "automation_coverage": { "percentage": 100, "covered": "K8s 내 공용계정 패턴", "not_covered": "사람 사용자 계정(외부 IdP)" },
    "exception_conditions": { "exception_namespaces": ["kube-system", "kube-public", "kube-node-lease"] },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- default(또는 빈) SA를 쓰는 Pod를 찾아낸 뒤, 예외 승인 여부 등은 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.service_account`, `cluster_pods.namespace`
- **사람 검토 영역** — 공용 계정 사용 예외 승인 기록 (시스템 namespace는 예외)
- **자동화 커버리지** — 100% (K8s 내 공용계정 패턴), 사람 사용자 계정은 제외
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 시스템 namespace(kube-system·kube-public·kube-node-lease) 등 예외 대상임
  - 공용/default SA 사용에 대한 책임자 예외 승인 기록이 있음 (인증범위 내 일반 워크로드면 전용 SA 부여 필요)
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준의 **계정 분리/공용계정 금지** 측면을 본다(공용 default SA 사용 탐지).
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### F-2.5.1-02 · 미사용(orphan) ServiceAccount 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.5.1-02",
  "name": "미사용(orphan) ServiceAccount 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount",
    "required_data": ["cluster_service_accounts", "cluster_role_bindings", "cluster_cluster_role_bindings"],
    "condition": { "operator": "orphan_serviceaccount" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.5.1", "match_strength": "indirect" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "불필요 계정 정기 점검/삭제 미흡", "match": "partial" }],
    "additional_review_items": ["이 SA들이 계획된 향후 사용을 위한 것인가", "정기 점검 미실시로 잔존한 계정인가", "회사의 계정 정기 점검 주기/기록 확인"],
    "manual_check_areas": ["최근 점검 기록"],
    "automation_coverage": { "percentage": 80, "covered": "K8s SA 정리 상태", "not_covered": "점검 절차 운영 여부" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 어떤 워크로드·바인딩에도 연결되지 않은 SA(orphan)를 찾아낸 뒤, 정기 점검 여부는 사람이 검토.
- **집계 대상 테이블** — `cluster_service_accounts`, `cluster_role_bindings`, `cluster_cluster_role_bindings`
- **사람 검토 영역** — 최근 점검 기록
- **자동화 커버리지** — 80% (SA 정리 상태), 점검 절차 운영 여부는 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 해당 SA가 계획된 예정 사용분으로 문서화돼 있거나, 계정 정기 점검 기록상 인지·관리되고 있음
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준 "…**불필요한 계정은 삭제**…" 중 미사용 계정 정리 측면을 본다.
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.1-01 · default ServiceAccount 사용
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.1-01",
  "name": "default ServiceAccount 사용",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "pod.spec.serviceAccountName", "op": "!=", "value": "default", "description": "Pod가 전용 ServiceAccount를 사용 (default SA 미사용)" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Pod가 default SA가 아닌 전용 SA를 쓰는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `service_account` (TEXT). 실제 적재되므로 정상 판정 가능.
- **JSON 필드 ↔ DB 매핑** — `pod.spec.serviceAccountName` = `cluster_pods.service_account`.
- 판정 기준: `service_account != 'default'` (빈 값도 default로 간주) ⇒ 전용 SA면 준수, default면 미준수
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준의 **공용계정 금지/계정 분리** 측면(default SA 미사용)을 본다.
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.1-02 · ServiceAccount owner 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.1-02",
  "name": "ServiceAccount owner 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "serviceaccount.metadata.labels.isms-p/owner", "op": "!=", "value": null, "description": "ServiceAccount에 소유자(owner) 라벨 존재" },
    { "field": "serviceaccount.metadata.labels.isms-p/purpose", "op": "!=", "value": null, "description": "ServiceAccount에 용도(purpose) 라벨 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- SA에 소유자·용도 라벨이 모두 붙어 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_service_accounts` / 컬럼: `name`, `namespace`, `secrets`(JSONB) 및 라벨. (`cluster_pods.service_account`로 사용 SA 연결)
- **JSON 필드 ↔ DB 매핑** — `serviceaccount.metadata.labels.isms-p/owner`, `.../purpose` 라벨 존재 여부.
- 판정 기준: owner != null AND purpose != null ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준의 **계정의 책임 주체·용도 식별**(누가 무엇을 위해 쓰는 계정인지)을 본다.
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.1-03 · 팀 간 ServiceAccount 공유
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.1-03",
  "name": "팀 간 ServiceAccount 공유",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "sa_shared_across_teams", "op": "==", "value": false, "description": "동일 ServiceAccount를 서로 다른 팀의 워크로드가 공유하지 않음" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 한 SA를 서로 다른 팀의 워크로드가 공유하는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods`(`service_account`), `cluster_workloads`(`kind`, `selector`, `template_labels` JSONB, `containers` JSONB)
- **JSON 필드 ↔ DB 매핑** — `sa_shared_across_teams`는 **파생값**. 계산 과정: ① 각 SA를 사용하는 워크로드 집합을 모은다 → ② 워크로드의 `template_labels`(또는 라벨)에서 팀 식별자(예: `team`)를 추출 → ③ 같은 SA를 쓰는 워크로드의 팀이 2개 이상이면 `True`.
- 판정 기준: `sa_shared_across_teams == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준의 **계정 분리(공유 금지)** 측면을 본다(팀 경계를 넘는 SA 공유 탐지).
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.1-GL01 · 계정·권한 생애주기 절차 수립
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.1-GL01",
  "name": "계정·권한 생애주기 절차 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정보시스템 및 개인정보처리시스템의 사용자 등록·해지 및 접근권한 부여·변경·말소에 관한 공식적인 절차를 수립·이행한다."],
  "compliance_indicators": [{ "description": "사용자 등록·해지 및 접근권한 부여·변경·말소 공식 절차를 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.5.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '계정·권한 생애주기(등록~말소) 절차'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「정보시스템 및 개인정보처리시스템의 사용자 등록·해지 및 접근권한 부여·변경·말소에 관한 공식적인 절차를 수립·이행한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준의 **계정 발급~삭제 절차** 전반의 공식화 여부를 본다.
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.1-GL02 · 직무별 최소권한 부여
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.1-GL02",
  "name": "직무별 최소권한 부여",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["사용자 등록·변경 시 직무별 접근권한 분류체계에 따라 업무상 필요한 최소한의 권한만 부여한다."],
  "compliance_indicators": [{ "description": "직무별 접근권한 분류체계에 따라 최소권한만 부여하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.5.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '직무별 최소권한 부여'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「사용자 등록·변경 시 직무별 접근권한 분류체계에 따라 업무상 필요한 최소한의 권한만 부여한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준 "…**업무상 필요한 최소한의 접근 권한을 부여**…" 중 **'최소권한 부여' 구절**.
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.1-GL03 · 계정 보안책임 인식
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.1-GL03",
  "name": "계정 보안책임 인식",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["사용자에게 계정 및 접근권한을 부여할 때 해당 계정의 보안책임이 본인에게 있음을 명확히 인식시킨다."],
  "compliance_indicators": [{ "description": "계정 보안책임이 본인에게 있음을 인식시키도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.5.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '계정 보안책임 인식'이 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「사용자에게 계정 및 접근권한을 부여할 때 해당 계정의 보안책임이 본인에게 있음을 명확히 인식시킨다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.1 인증기준의 계정 발급 운영 측면, 즉 **사용자에게 보안책임을 인식시키는 절차**를 본다.
- ISMS-P 2.5.1 사용자 계정 관리 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

## 2.5.2 사용자 식별

### F-2.5.2-01 · 추측 가능한 명칭의 ServiceAccount 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.5.2-01",
  "name": "추측 가능한 명칭의 ServiceAccount 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount",
    "required_data": ["cluster_service_accounts.name"],
    "condition": { "operator": "regex_match", "field": "name", "pattern": "^(admin|root|test|temp|guest)(-.*)?$" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.5.2", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "admin, guest, test 등 추측 가능한 ID 운영", "match": "direct" }],
    "additional_review_items": ["해당 SA가 인증범위 내 자산인가", "명명 자체보다 권한 범위 점검(F-2.5.5와 결합)", "회사 명명 규칙 문서와 비교"],
    "automation_coverage": { "percentage": 80, "covered": "K8s SA 명명 점검", "not_covered": "사람 사용자 ID 체계" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- admin/root/test/temp/guest 류의 추측 가능한 SA 이름을 찾아낸 뒤, 명명 규칙·권한 범위는 사람이 검토.
- **집계 대상 테이블** — `cluster_service_accounts.name`
- **사람 검토 영역** — 회사 명명 규칙 문서, 권한 범위(F-2.5.5 결합)
- **자동화 커버리지** — 80% (SA 명명 점검), 사람 사용자 ID 체계는 제외
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 회사 명명 규칙 문서상 허용된 명칭이거나, 해당 SA의 권한이 최소화돼 위험이 통제됨(F-2.5.5 결합 확인)
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준의 **고유 식별/추측 어려운 식별자** 측면을 본다.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### F-2.5.2-02 · 일반 명명 패턴 ServiceAccount 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.5.2-02",
  "name": "일반 명명 패턴 ServiceAccount 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount",
    "required_data": ["cluster_service_accounts.name"],
    "condition": { "operator": "regex_match", "field": "name", "pattern": "^(user|account|sa)[0-9]+$" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.5.2", "match_strength": "indirect" }],
    "additional_review_items": ["용도가 의미적으로 식별 가능한가", "운영 표준 명명 규칙과 일치하는가"],
    "automation_coverage": { "percentage": 80, "covered": "명명 규칙 점검만", "not_covered": "실제 사용 패턴" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- user1/account2/sa3 류의 무의미한 일련번호 명명 SA를 찾아낸 뒤, 식별 가능성은 사람이 검토.
- **집계 대상 테이블** — `cluster_service_accounts.name`
- **사람 검토 영역** — 운영 표준 명명 규칙
- **자동화 커버리지** — 80% (명명 규칙 점검), 실제 사용 패턴은 제외
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 운영 표준 명명 규칙 문서상 용도가 의미적으로 식별 가능하도록 매핑·관리됨
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준의 **식별자가 사용자/용도를 고유하게 식별**하는지 측면을 본다.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.2-01 · 추측 가능한 SA 이름
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.2-01",
  "name": "추측 가능한 SA 이름",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "guessable_name_patterns": ["^admin$", "^root$", "^test$", "^user$", "^sa$", "^service$", "^app$", "^demo$", "^temp$", "^tmp$"],
  "compliance_indicators": [
    { "field": "sa_name_is_guessable", "op": "==", "value": false, "description": "ServiceAccount 이름이 추측 불가능한 고유 식별명 사용" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- SA 이름이 추측 가능한 흔한 명칭인지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `service_account` (TEXT)
- **JSON 필드 ↔ DB 매핑** — `sa_name_is_guessable`는 **파생값**. 계산 과정: `service_account` 이름을 `guessable_name_patterns`(admin·root·test·user·sa·service·app·demo·temp·tmp) 정규식과 대조해 하나라도 매칭되면 `True`.
- 판정 기준: `sa_name_is_guessable == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준의 **추측 어려운 고유 식별자** 사용 측면을 본다.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.2-02 · 일반 명명 패턴
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.2-02",
  "name": "일반 명명 패턴",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "generic_naming_patterns": ["^sa-[0-9]+$", "^serviceaccount-[0-9]+$", "^svc-account-[0-9]+$", "^user[0-9]+$", "^account[0-9]+$"],
  "compliance_indicators": [
    { "field": "sa_name_is_generic", "op": "==", "value": false, "description": "ServiceAccount 이름이 워크로드·기능을 식별할 수 있는 명명규칙 준수" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- SA 이름이 무의미한 일련번호식 일반 패턴인지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `service_account` (TEXT)
- **JSON 필드 ↔ DB 매핑** — `sa_name_is_generic`는 **파생값**. 계산 과정: `service_account` 이름을 `generic_naming_patterns`(sa-N·serviceaccount-N·svc-account-N·userN·accountN) 정규식과 대조해 매칭되면 `True`.
- 판정 기준: `sa_name_is_generic == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준의 **식별자가 워크로드/기능을 고유하게 식별**하는지를 본다.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.2-GL01 · 사용자별 유일 식별자 부여
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.2-GL01",
  "name": "사용자별 유일 식별자 부여",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정보시스템 및 개인정보·중요정보에 대한 접근을 사용자별로 고유하게 식별할 수 있도록 유일한 식별자를 부여한다."],
  "compliance_indicators": [{ "description": "사용자별로 고유하게 식별 가능한 유일 식별자를 부여하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.5.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '사용자별 유일 식별자 부여'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「정보시스템 및 개인정보·중요정보에 대한 접근을 사용자별로 고유하게 식별할 수 있도록 유일한 식별자를 부여한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준 "…**사용자별로 고유하게 식별**…" 중 **'유일 식별자 부여' 구절**.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.2-GL02 · 추측 가능한 식별자 사용 제한
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.2-GL02",
  "name": "추측 가능한 식별자 사용 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["추측하기 쉬운 식별자(root, admin, test 등)의 사용을 제한한다."],
  "compliance_indicators": [{ "description": "추측하기 쉬운 식별자 사용을 제한하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.5.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '추측 가능한 식별자 사용 제한'이 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「추측하기 쉬운 식별자(root, admin, test 등)의 사용을 제한한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준의 식별 신뢰성, 즉 **추측 쉬운 식별자 제한** 규정 여부를 본다.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.2-GL03 · 공유 식별자 통제
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.2-GL03",
  "name": "공유 식별자 통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["불가피하게 동일한 식별자를 공유하는 경우 그 사유와 타당성을 검토하고 보완대책을 마련하여 책임자의 승인을 받는다."],
  "compliance_indicators": [{ "description": "식별자 공유 시 사유·타당성 검토와 보완대책, 책임자 승인을 받도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.5.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- 회사 지침서에 '공유 식별자 통제(승인 절차)'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「불가피하게 동일한 식별자를 공유하는 경우 그 사유와 타당성을 검토하고 보완대책을 마련하여 책임자의 승인을 받는다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.2 인증기준 "…**동일한 사용자 계정을 공유하여 사용하지 않도록**…" 중 **불가피한 공유 시 통제·승인** 구절.
- ISMS-P 2.5.2 사용자 식별 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

## 2.5.5 특수 계정 및 권한 관리

### F-2.5.5-01 · 클러스터 최고 권한 보유 SA 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.5.5-01",
  "name": "클러스터 최고 권한 보유 SA 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount + RBAC chain",
    "required_data": ["cluster_pods.service_account", "cluster_role_bindings", "cluster_cluster_role_bindings", "cluster_roles", "cluster_cluster_roles"],
    "condition": { "operator": "any_of", "conditions": [{ "binding_target": "cluster-admin" }, { "rules_contain": { "verbs": ["*"], "resources": ["*"] } }, { "cluster_scope_secret_access": ["get", "list", "watch"] }] },
    "manual_check_areas": ["권한 부여 결재 기록"]
  }
}
```

- cluster-admin 바인딩·와일드카드 권한·클러스터 전체 Secret 열람권을 가진 SA를 찾아낸 뒤, 권한 부여 결재 기록은 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.service_account`, `cluster_role_bindings`, `cluster_cluster_role_bindings`, `cluster_roles`, `cluster_cluster_roles`
- **사람 검토 영역** — 권한 부여 결재 기록
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 해당 최고권한(cluster-admin 등) 부여가 신청·승인 결재로 정당화되고, 별도 식별·감사(책임추적성) 대상으로 관리됨
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준 "…특수 목적 계정·권한은 **최소한으로 부여**하고 별도로 식별·통제…" 중 과도한 최고 권한 보유 여부를 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### F-2.5.5-02 · 위험 RBAC 권한 보유 SA 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.5.5-02",
  "name": "위험 RBAC 권한 보유 SA 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount + RBAC chain",
    "required_data": ["cluster_role_bindings", "cluster_cluster_role_bindings", "cluster_roles", "cluster_cluster_roles"],
    "condition": { "operator": "any_dangerous_verb", "patterns": [{ "name": "pod_exec", "resource": "pods/exec", "verbs": ["create", "*"] }, { "name": "secret_write", "resource": "secrets", "verbs": ["create", "update", "patch", "*"] }, { "name": "rbac_escalate", "resource": "*", "verbs": ["escalate"] }, { "name": "impersonate", "resource": "users|groups|serviceaccounts", "verbs": ["impersonate"] }] },
    "manual_check_areas": ["RBAC 정책 문서 확인", "권한 부여 결재 기록"]
  }
}
```

- pods/exec·secret 쓰기·escalate·impersonate 같은 위험 verb를 가진 SA를 찾아낸 뒤, RBAC 정책·결재 기록은 사람이 검토.
- **집계 대상 테이블** — `cluster_role_bindings`, `cluster_cluster_role_bindings`, `cluster_roles`, `cluster_cluster_roles`
- **사람 검토 영역** — RBAC 정책 문서, 권한 부여 결재 기록
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 위험 RBAC 권한이 결재 승인 + RBAC 정책 문서상 정당화되고, 예외 사유(rbac-exception)·감사로 통제됨
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **최소권한**, 즉 위험한 권한 조합 보유 여부를 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-01 · ServiceAccount 특수 권한 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-01",
  "name": "ServiceAccount 특수 권한 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "has_cluster_admin", "op": "==", "value": false, "description": "cluster-admin 바인딩 없음" },
    { "field": "has_wildcard_permission", "op": "==", "value": false, "description": "verbs:* + resources:* 와일드카드 권한 없음" },
    { "field": "has_cluster_wide_secrets", "op": "==", "value": false, "description": "클러스터 전체 Secret 접근 권한 없음" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required" }
}
```

- SA가 cluster-admin·와일드카드·클러스터 전체 Secret 권한을 갖지 않는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_roles`, `cluster_role_bindings`, `cluster_cluster_roles`, `cluster_cluster_role_bindings` / 컬럼: `rules`, `role_ref`, `subjects` (JSONB)
- **JSON 필드 ↔ DB 매핑** — 세 필드 모두 **파생값**. 계산 과정: ① bindings의 `subjects`에서 대상 SA를 찾아 `role_ref`로 연결된 role을 추적 → ② `has_cluster_admin`: role_ref가 `cluster-admin`인지 → ③ `has_wildcard_permission`: 연결된 role의 `rules`에 `verbs:["*"]`+`resources:["*"]` 존재 여부 → ④ `has_cluster_wide_secrets`: ClusterRole에 `secrets` get/list/watch 존재 여부.
- 판정 기준: 세 파생값 모두 `False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **특수 권한 최소화**(최고 권한 미보유)를 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-02 · 위험 RBAC verb 조합 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-02",
  "name": "위험 RBAC verb 조합 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "dangerous_verb_combinations": [
    { "name": "pod_exec_attach", "verbs": ["create", "get"], "resources": ["pods/exec", "pods/attach", "pods/portforward"], "risk": "컨테이너 내부 임의 명령 실행" },
    { "name": "secret_read_cluster_wide", "verbs": ["get", "list", "watch"], "resources": ["secrets"], "scope": "cluster_wide", "risk": "클러스터 전체 비밀정보 열람" },
    { "name": "secret_write", "verbs": ["create", "update", "patch", "delete"], "resources": ["secrets"], "risk": "비밀정보 변조·삭제" },
    { "name": "rbac_escalate", "verbs": ["escalate"], "resources": ["clusterroles", "roles"], "risk": "RBAC 권한 자체 상승" },
    { "name": "rbac_bind", "verbs": ["bind"], "resources": ["clusterroles", "roles"], "risk": "임의 권한 바인딩" },
    { "name": "impersonate", "verbs": ["impersonate"], "resources": ["users", "groups", "serviceaccounts"], "risk": "다른 계정 가장하여 API 호출" },
    { "name": "node_proxy", "verbs": ["get", "create"], "resources": ["nodes/proxy"], "risk": "kubelet API 직접 접근" },
    { "name": "sa_token_request", "verbs": ["create"], "resources": ["serviceaccounts/token"], "risk": "임의 ServiceAccount 토큰 발급" }
  ],
  "compliance_indicators": [
    { "field": "has_dangerous_verb_combo", "op": "==", "value": false, "description": "위험 verb 조합 미보유" }
  ],
  "exception_check": { "annotation": "rbac-exception/justification", "system_namespaces": ["kube-system", "kube-node-lease"] },
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required" }
}
```

- SA가 위험한 verb·resource 조합(exec, secret 쓰기, escalate/bind, impersonate, node/proxy, token 발급)을 갖는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_roles`, `cluster_role_bindings`, `cluster_cluster_roles`, `cluster_cluster_role_bindings` / 컬럼: `rules`, `role_ref`, `subjects` (JSONB)
- **JSON 필드 ↔ DB 매핑** — `has_dangerous_verb_combo`는 **파생값**. 계산 과정: SA에 연결된 role의 `rules`를 순회하며 `dangerous_verb_combinations` 8종 각각의 verb+resource 조합과 매칭 → 하나라도 매칭되고 예외 annotation(`rbac-exception/justification`)·시스템 namespace가 아니면 `True`.
- 판정 기준: `has_dangerous_verb_combo == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **권한 최소화**(특권 상승·우회로 이어지는 위험 권한 배제)를 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-GL01 · 특수 권한 정기 검토·회수 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-GL01",
  "name": "특수 권한 현황을 정기적으로 검토하고 불필요한 권한을 회수하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["특수 권한 현황을 분기 이내 주기로 정기 검토하고 불필요한 권한을 회수하도록 규정한다."],
  "compliance_indicators": [{ "field": "검토주기", "op": "<=", "value": "분기", "description": "특수 권한 검토 주기를 분기 이내로 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- 회사 지침서에 '특수 권한 정기 검토(분기 이내)·회수'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「특수 권한 현황을 분기 이내 주기로 정기 검토하고 불필요한 권한을 회수하도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **별도 식별·통제** 운영, 즉 정기 검토·회수 주기 규정을 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-GL02 · 불필요한 특수 권한 즉시 회수 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-GL02",
  "name": "불필요한 특수 권한을 즉시 회수하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["불필요한 특수 권한을 발견 즉시 회수하도록 규정한다."],
  "compliance_indicators": [{ "description": "불필요한 특수 권한 발견 시 즉시 회수 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- 회사 지침서에 '불필요 특수 권한 즉시 회수'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「불필요한 특수 권한을 발견 즉시 회수하도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **권한 최소화 유지**, 즉 불필요 권한 발견 시 즉시 회수 규정을 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-GL03 · 특수 계정 책임추적성(로깅·감사) 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-GL03",
  "name": "특수 계정 사용 시 책임추적성(로깅·감사)을 확보하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["특수 계정 사용 시 로그 기록 및 감사를 통해 책임추적성을 확보하도록 규정한다."],
  "compliance_indicators": [{ "description": "특수 계정 사용 시 로그 기록 및 감사 수행 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- 회사 지침서에 '특수 계정 책임추적성(로깅·감사)'이 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「특수 계정 사용 시 로그 기록 및 감사를 통해 책임추적성을 확보하도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **별도 식별·통제**, 즉 특수 계정 사용에 대한 책임추적성 확보 규정을 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-GL04 · 특수 계정 목록 최신 관리 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-GL04",
  "name": "특수 계정 목록을 최신 상태로 관리하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["특수 계정 목록을 별도로 식별하여 최신 상태로 관리하도록 규정한다."],
  "compliance_indicators": [{ "description": "특수 계정 목록을 최신 상태로 유지·관리 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- 회사 지침서에 '특수 계정 목록 최신 관리'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「특수 계정 목록을 별도로 식별하여 최신 상태로 관리하도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준 "…**별도로 식별하여 통제**…" 중 특수 계정 목록의 식별·최신 유지를 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-GL05 · 특수 권한 부여 승인 절차 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-GL05",
  "name": "특수 권한 부여 시 승인 절차를 거치도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["특수 권한 부여 시 신청·승인(결재) 절차를 거치도록 규정한다."],
  "compliance_indicators": [{ "description": "특수 권한 부여 시 승인 절차(신청·결재) 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- 회사 지침서에 '특수 권한 부여 승인 절차'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「특수 권한 부여 시 신청·승인(결재) 절차를 거치도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **통제 절차**, 즉 특수 권한 부여 시 신청·결재 통제를 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

### R-2.5.5-GL06 · 특수 계정 공동 사용 금지 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.5-GL06",
  "name": "특수 계정의 공동 사용을 금지하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["특수 계정의 공동 사용을 금지하고 개인별로 계정을 부여하도록 규정한다."],
  "compliance_indicators": [{ "description": "특수 계정의 공동 사용 금지 및 개인별 계정 부여 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- 회사 지침서에 '특수 계정 공동 사용 금지(개인별 부여)'가 규정돼 있는지 RAG로 판정한다.
- **점검 기준 문장(keywords)**: 「특수 계정의 공동 사용을 금지하고 개인별로 계정을 부여하도록 규정한다.」
- 판정: 충족 / 미충족 / 확인불가
- **인증기준의 어느 부분을 보는가** — 2.5.5 인증기준의 **별도 식별·통제**, 즉 특수 계정의 공동 사용 금지·개인별 부여 규정을 본다.
- ISMS-P 2.5.5 특수 계정 및 권한 관리 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조

## 2.5.4 비밀번호 관리

> ⚠️ R-2.5.4-03~15(설정/증적 기반 측정 룰 13개)는 **K8s 전용 스캐너 범위 밖**이라 제거했다. 비밀번호는 OS/AD/IAM/DB/WAS·앱 로그인 등 클러스터 밖 대상이고(K8s ServiceAccount는 비밀번호가 없음), 현 엔진에는 이를 수집·평가할 데이터 소스(`cluster_*` 테이블)나 코드가 없다. 따라서 2.5.4는 지침·정책 점검(GL) 룰만 유지한다.
> 아래 R-2.5.4-GL01~GL15는 모두 📄 지침·정책 점검(RAG)이며, 공통적으로 ISMS-P 2.5.4 비밀번호 관리 인증기준("법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.")의 **비밀번호 관리절차 규정 여부**를 항목별로 나눠 본다. 법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항·제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항.

### R-2.5.4-GL01 · 비밀번호 관리 정책 문서 존재(생성규칙·변경주기·저장방법 포함)
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL01",
  "name": "비밀번호 관리 정책 문서가 존재하고 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호 관리 정책 문서가 존재하며 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정한다."],
  "compliance_indicators": [{ "description": "지침서에 비밀번호 생성규칙, 변경주기, 저장방법이 모두 명시" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호 관리 정책 문서가 존재하며 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — '비밀번호 관리절차 수립'의 **존재와 포괄성**(생성·변경·저장 규칙 모두 포함)을 본다.

### R-2.5.4-GL02 · 비밀번호 최소 길이 8자 이상 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL02",
  "name": "비밀번호 최소 길이를 8자 이상으로 설정하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호 최소 길이를 8자 이상으로 설정하도록 규정한다."],
  "compliance_indicators": [{ "field": "최소길이", "op": ">=", "value": 8, "description": "비밀번호 최소 8자 이상 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호 최소 길이를 8자 이상으로 설정하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **생성 규칙(최소 길이)** 규정 여부를 본다.

### R-2.5.4-GL03 · 비밀번호 최대 사용 기간 90일 이하 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL03",
  "name": "비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정한다."],
  "compliance_indicators": [{ "field": "최대사용일수", "op": "<=", "value": 90, "description": "비밀번호 최대 사용기간 90일 이하 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **변경 주기(최대 사용기간)** 규정 여부를 본다.

### R-2.5.4-GL04 · 임시 비밀번호 최초 로그인 시 변경 강제 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL04",
  "name": "초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정한다."],
  "compliance_indicators": [{ "description": "초기/임시 비밀번호 발급 시 최초 로그인 시 강제 변경 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **임시 비밀번호 강제 변경** 규정 여부를 본다.

### R-2.5.4-GL05 · 비밀번호 일방향 암호화 저장 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL05",
  "name": "비밀번호를 일방향 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호를 일방향(단방향) 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정한다."],
  "compliance_indicators": [{ "description": "비밀번호 일방향 암호화 저장 및 평문 저장 금지 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호를 일방향(단방향) 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **저장 방법(일방향 암호화)** 규정 여부를 본다.

### R-2.5.4-GL06 · 입력 오류 시 계정 잠금 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL06",
  "name": "비밀번호 입력 오류 시 계정 잠금 처리하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호 입력 오류가 일정 횟수 누적되면 계정을 잠금 처리하도록 규정한다."],
  "compliance_indicators": [{ "field": "잠금횟수", "op": "<=", "value": 5, "description": "5회 이내 입력 오류 시 계정 잠금 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호 입력 오류가 일정 횟수 누적되면 계정을 잠금 처리하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **외부 위협 대응(무차별 대입 방지·계정 잠금)** 규정 여부를 본다.

### R-2.5.4-GL07 · 관리자·중요 시스템 MFA 적용 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL07",
  "name": "관리자 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["관리자 계정 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정한다."],
  "compliance_indicators": [{ "description": "관리자·중요 시스템 접근 시 다중인증(MFA) 적용 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「관리자 계정 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **강화 인증(MFA)** 규정 여부를 본다.

### R-2.5.4-GL08 · 로그인 실패 메시지 식별자 구분 노출 금지 규정
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL08",
  "name": "로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정한다."],
  "compliance_indicators": [{ "description": "로그인 실패 시 아이디·비밀번호 구분 정보 미노출 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **외부 위협 대응(식별자 추측 방지)** 규정 여부를 본다.

### R-2.5.4-GL09 · 추측하기 쉬운 비밀번호 사용 금지 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 WR-02 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL09",
  "name": "추측하기 쉬운 비밀번호 사용 금지",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["생일·전화번호·아이디처럼 추측하기 쉬운 비밀번호를 쓰지 못하도록 규정한다."],
  "compliance_indicators": [{ "description": "추측하기 쉬운 비밀번호 사용 금지 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「생일·전화번호·아이디처럼 추측하기 쉬운 비밀번호를 쓰지 못하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **생성 규칙(추측 가능 비번 금지)** 규정 여부를 본다.

### R-2.5.4-GL10 · 반복·연속 문자 비밀번호 제한 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 WR-03 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL10",
  "name": "반복·연속 문자 비밀번호 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["같은 문자 반복이나 연속된 숫자로 된 비밀번호를 제한하도록 규정한다."],
  "compliance_indicators": [{ "description": "반복·연속 문자 비밀번호 제한 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「같은 문자 반복이나 연속된 숫자로 된 비밀번호를 제한하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **생성 규칙(반복·연속 문자 제한)** 규정 여부를 본다.

### R-2.5.4-GL11 · 비밀번호 입력 시 마스킹 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 MP-02 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL11",
  "name": "비밀번호 입력 시 화면 가림(마스킹)",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호를 입력하거나 변경할 때 화면에 마스킹 처리하도록 규정한다."],
  "compliance_indicators": [{ "description": "비밀번호 입력 시 화면 가림(마스킹) 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호를 입력하거나 변경할 때 화면에 마스킹 처리하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **입력 시 노출 방지(마스킹)** 규정 여부를 본다.

### R-2.5.4-GL12 · 비밀번호 기록·보관 제한 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 MP-03 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL12",
  "name": "비밀번호 기록·보관 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호를 종이·파일·모바일 등에 기록·보관하는 것을 제한하고 부득이하면 암호화하도록 규정한다."],
  "compliance_indicators": [{ "description": "비밀번호 기록·보관 제한 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호를 종이·파일·모바일 등에 기록·보관하는 것을 제한하고 부득이하면 암호화하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **보관·취급 통제(기록 제한)** 규정 여부를 본다.

### R-2.5.4-GL13 · 유출 의심 시 즉시 변경 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 MP-04 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL13",
  "name": "유출 의심 시 즉시 변경",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호 노출이나 침해가 의심되면 지체 없이 변경하도록 규정한다."],
  "compliance_indicators": [{ "description": "유출 의심 시 즉시 변경 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호 노출이나 침해가 의심되면 지체 없이 변경하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **침해 대응(유출 의심 시 즉시 변경)** 규정 여부를 본다.

### R-2.5.4-GL14 · 분실 시 본인확인 후 재발급 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 MP-05 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL14",
  "name": "분실 시 본인확인 후 재발급",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["비밀번호 분실 시 본인 확인을 거쳐 안전하게 재발급하도록 규정한다."],
  "compliance_indicators": [{ "description": "분실 시 본인확인 후 재발급 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「비밀번호 분실 시 본인 확인을 거쳐 안전하게 재발급하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **재발급 통제(본인확인)** 규정 여부를 본다.

### R-2.5.4-GL15 · 관리자 비밀번호 별도 강화 관리 규정
📄 지침·정책 점검(RAG) · 🆕 구 R-2.5.4-02 MP-07 이관

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.5.4-GL15",
  "name": "관리자 비밀번호 별도 강화 관리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["관리자 비밀번호는 일반 사용자와 분리해 더 강한 기준으로 관리하도록 규정한다."],
  "compliance_indicators": [{ "description": "관리자 비밀번호 별도 강화 관리 규정" }],
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment" }
}
```

- **점검 기준 문장(keywords)**: 「관리자 비밀번호는 일반 사용자와 분리해 더 강한 기준으로 관리하도록 규정한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 비밀번호 관리절차 중 **권한별 차등 강화(관리자 별도 기준)** 규정 여부를 본다.

## 2.6.1 네트워크 접근

### F-2.6.1-01 · NetworkPolicy 적용 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.6.1-01",
  "name": "NetworkPolicy 적용 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Namespace + NetworkPolicy",
    "required_data": ["cluster_namespaces", "cluster_network_policies"],
    "condition": { "operator": "default_deny_coverage_report" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.6.1", "match_strength": "indirect" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "서버팜과 사무망 미분리", "match": "partial" }],
    "additional_review_items": ["K8s NetworkPolicy 외 네트워크 분리 통제가 적용되어 있는가", "미적용 namespace가 인증범위 내인가", "운영망/개발망/DMZ 등 영역별 분리 설계"],
    "manual_check_areas": ["네트워크 분리 설계 문서", "VPC/Subnet/Security Group 정책", "사내망 IP 관리 대장"],
    "automation_coverage": { "percentage": 40, "covered": "K8s NetworkPolicy 적용 현황", "not_covered": "K8s 외 네트워크 통제, 사내망 단말 인증" },
    "alternative_controls": ["VPC subnet 분리 + Security Group", "Istio AuthorizationPolicy", "Calico GlobalNetworkPolicy", "별도 클러스터 운영"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- namespace별 default-deny 적용 커버리지를 집계한 뒤, K8s 외 네트워크 분리 통제는 사람이 검토.
- **집계 대상 테이블** — `cluster_namespaces`, `cluster_network_policies`
- **사람 검토 영역** — 네트워크 분리 설계 문서, VPC/Subnet/Security Group 정책, 사내망 IP 관리 대장
- **자동화 커버리지** — 40% (K8s NetworkPolicy 적용 현황만)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 영역 분리가 VPC 서브넷+Security Group / 별도 클러스터 / Istio AuthorizationPolicy / Calico GlobalNetworkPolicy 등으로 적용됨
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준 "…업무 목적 및 중요도에 따라 **네트워크 분리…와 접근통제**…" 중 분리 적용 현황을 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### F-2.6.1-02 · CNI NetworkPolicy 강제 상태
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.6.1-02",
  "name": "CNI NetworkPolicy 강제 상태",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Cluster Workload",
    "required_data": ["cluster_workloads"],
    "condition": { "operator": "daemonset_exists", "namespace": "kube-system", "name_patterns": ["calico-node", "cilium", "calico-kube-controllers"] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.6.1", "match_strength": "indirect" }],
    "additional_review_items": ["미발견 시 K8s NetworkPolicy 무효화 가능성 - 외부 통제로 분리 확인", "발견 시 정책 강제 옵션 활성화 여부(도구는 옵션 미확인)"],
    "manual_check_areas": ["CNI 설정 문서", "Network 강제 정책 운영 상태"],
    "automation_coverage": { "percentage": 50, "covered": "CNI 배포 여부", "not_covered": "정책 강제 옵션 활성화 상태" },
    "alternative_controls": ["AWS VPC CNI + Security Group", "Service Mesh", "외부 NetFW"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- NetworkPolicy를 강제할 수 있는 CNI(calico/cilium 등) DaemonSet 존재를 확인한 뒤, 강제 옵션 활성화는 사람이 검토.
- **집계 대상 테이블** — `cluster_workloads`
- **사람 검토 영역** — CNI 설정 문서, Network 강제 정책 운영 상태
- **자동화 커버리지** — 50% (CNI 배포 여부만)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - AWS VPC CNI+Security Group, Service Mesh, 외부 방화벽 등으로 통신 통제가 강제되고 있음(정책 강제 CNI 미발견이어도)
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 **접근통제 실효성**, 즉 NetworkPolicy가 실제로 강제되는 기반(CNI)이 있는지를 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### F-2.6.1-03 · Cross-namespace 통신 통제 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.6.1-03",
  "name": "Cross-namespace 통신 통제 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "NetworkPolicy + Namespace",
    "required_data": ["cluster_network_policies", "cluster_namespaces", "cluster_pods"],
    "condition": { "operator": "cross_ns_traffic_control_report" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.6.1", "match_strength": "indirect" }],
    "additional_review_items": ["영역별 분리가 cluster 또는 VPC 분리로 이뤄지면 K8s 통제 불필요", "단일 클러스터 내 영역 분리라면 K8s 통제 적용 권장"],
    "manual_check_areas": ["네트워크 분리 설계 문서", "VPC 분리 정책"],
    "automation_coverage": { "percentage": 50, "covered": "K8s NetworkPolicy 차원의 cross-ns 통제", "not_covered": "VPC/Service Mesh 차원의 통제" },
    "alternative_controls": ["VPC 라우팅", "Service Mesh", "별도 클러스터"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- namespace 간 통신 통제 현황을 집계한 뒤, VPC/Service Mesh 차원의 통제는 사람이 검토.
- **집계 대상 테이블** — `cluster_network_policies`, `cluster_namespaces`, `cluster_pods`
- **사람 검토 영역** — 네트워크 분리 설계 문서, VPC 분리 정책
- **자동화 커버리지** — 50% (K8s 차원 cross-ns 통제만)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 운영/개발 영역이 별도 VPC(서브넷+SG) 또는 별도 클러스터로 분리됨
  - Service Mesh AuthorizationPolicy/mTLS로 namespace 간 통신이 차단됨
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 **영역 간 분리·접근통제**가 namespace 경계에서 적용되는지를 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-01 · hostNetwork 사용 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-01",
  "name": "hostNetwork 사용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "pod.spec.hostNetwork", "op": "!=", "value": true, "description": "hostNetwork 비활성" },
    { "field": "pod.spec.hostPID", "op": "!=", "value": true, "description": "hostPID 비활성" },
    { "field": "pod.spec.hostIPC", "op": "!=", "value": true, "description": "hostIPC 비활성" }
  ],
  "exception_check": { "annotation": "security-exception/justification", "system_namespaces": ["kube-system", "kube-node-lease", "amazon-cloudwatch"] },
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Pod가 노드 네트워크/PID/IPC 네임스페이스를 공유(host*)하지 않는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `host_network` (BOOL). (hostPID·hostIPC도 Pod 스펙 동일 위치에서 확인)
- **JSON 필드 ↔ DB 매핑** — `pod.spec.hostNetwork` = `cluster_pods.host_network`; `hostPID`/`hostIPC`는 동일 Pod 스펙의 대응 플래그.
- 판정 기준: hostNetwork·hostPID·hostIPC 모두 `!= true`(예외 annotation·시스템 namespace 제외) ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 **네트워크 경계 우회 차단**, 즉 Pod가 노드 네트워크 격리를 깨지 않는지를 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-02 · NetworkPolicy 적용 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-02",
  "name": "NetworkPolicy 적용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "has_default_deny", "op": "==", "value": true, "description": "default-deny(Ingress+Egress) NetworkPolicy 존재" },
    { "field": "has_matching_policy", "op": "==", "value": true, "description": "Pod에 매칭되는 허용 NetworkPolicy 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- namespace에 default-deny가 있고 Pod에 매칭되는 허용 정책이 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_network_policies` / 컬럼: `pod_selector`, `policy_types`, `ingress_rules`, `egress_rules` (JSONB)
- **JSON 필드 ↔ DB 매핑** — 두 필드 모두 **파생값**. ① `has_default_deny`: 해당 ns에 `pod_selector={}`이고 `policy_types`에 Ingress+Egress가 있으며 룰이 비어 있는 정책 존재 여부 → ② `has_matching_policy`: 대상 Pod 라벨이 어떤 정책의 `pod_selector`에 매칭되는지.
- 판정 기준: `has_default_deny == True` AND `has_matching_policy == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 **접근통제(기본 차단 후 필요 통신만 허용)** 적용 여부를 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-03 · CNI NetworkPolicy 강제 지원 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-03",
  "name": "CNI NetworkPolicy 강제 지원 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "supported_cni_indicators": [
    { "name": "calico", "daemonset_name": "calico-node", "policy_enforcement": "native" },
    { "name": "cilium", "daemonset_name": "cilium", "policy_enforcement": "native" },
    { "name": "weave", "daemonset_name": "weave-net", "policy_enforcement": "native" },
    { "name": "aws-vpc-cni", "daemonset_name": "aws-node", "policy_enforcement": "conditional", "required_env": { "ENABLE_NETWORK_POLICY": "true" } }
  ],
  "compliance_indicators": [
    { "field": "has_policy_capable_cni", "op": "==", "value": true, "description": "NetworkPolicy 강제 가능한 CNI DaemonSet 존재" },
    { "field": "policy_enforcement_enabled", "op": "==", "value": true, "description": "aws-vpc-cni 경우 aws-node DaemonSet env에 ENABLE_NETWORK_POLICY=true 설정" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- NetworkPolicy를 강제할 수 있는 CNI가 배포되고 강제 옵션이 켜져 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_workloads` / 컬럼: `kind`, `selector`, `template_labels`(JSONB), `containers`(JSONB)
- **JSON 필드 ↔ DB 매핑** — 두 필드 모두 **파생값**. ① `has_policy_capable_cni`: `cluster_workloads`에 calico-node/cilium/weave-net/aws-node DaemonSet 존재 여부 → ② `policy_enforcement_enabled`: aws-vpc-cni인 경우 `aws-node`의 `containers[].env`에서 `ENABLE_NETWORK_POLICY=true` 여부.
- 판정 기준: `has_policy_capable_cni == True` AND `policy_enforcement_enabled == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 **접근통제 실효성**(정책 강제 기반 존재)을 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-04 · cross-namespace 통신 통제 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-04",
  "name": "cross-namespace 통신 통제 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "cross_ns_egress_controlled", "op": "==", "value": true, "description": "Pod에 매칭되는 egress NetworkPolicy로 cross-namespace 통신 통제" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Pod의 namespace 간 아웃바운드 통신이 egress 정책으로 통제되는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_network_policies` / 컬럼: `pod_selector`, `policy_types`, `ingress_rules`, `egress_rules` (JSONB)
- **JSON 필드 ↔ DB 매핑** — `cross_ns_egress_controlled`는 **파생값**. 계산 과정: 대상 Pod에 매칭되는 egress 정책의 `egress_rules`에 다른 namespace로의 통신을 제한하는 규칙(namespaceSelector 기반 허용/차단)이 있는지 확인.
- 판정 기준: `cross_ns_egress_controlled == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 **영역 간 접근통제**(namespace 경계 egress 통제)를 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-GL01 · 비인가 네트워크 접근 통제 절차
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-GL01",
  "name": "비인가 네트워크 접근 통제 절차",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["네트워크에 대한 비인가 접근을 통제하기 위해 IP 관리, 단말 인증 등 관리절차를 수립·이행한다."],
  "compliance_indicators": [{ "description": "IP 관리·단말 인증 등 비인가 네트워크 접근 통제 절차를 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「네트워크에 대한 비인가 접근을 통제하기 위해 IP 관리, 단말 인증 등 관리절차를 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준 "…**IP 관리, 단말 인증 등 관리절차를 수립·이행**…" 구절.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-GL02 · IP 부여 기준 및 사설 IP 할당
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-GL02",
  "name": "IP 부여 기준 및 사설 IP 할당",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["네트워크 대역별 IP 주소 부여 기준을 마련하고, 외부 연결이 필요하지 않은 시스템(DB 서버 등)에는 사설 IP를 할당한다."],
  "compliance_indicators": [{ "description": "대역별 IP 부여 기준 마련 및 외부 연결 불필요 시스템의 사설 IP 할당을 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「네트워크 대역별 IP 주소 부여 기준을 마련하고, 외부 연결이 필요하지 않은 시스템(DB 서버 등)에는 사설 IP를 할당한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준 "…**IP 관리**…" 의 구체 운영(대역별 부여 기준·사설 IP 할당)을 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-GL03 · 업무 중요도 기반 네트워크 분리
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-GL03",
  "name": "업무 중요도 기반 네트워크 분리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["업무 목적 및 중요도에 따라 네트워크를 영역별(DMZ, 서버팜, DB존, 개발존 등)로 분리하고 접근통제를 적용한다."],
  "compliance_indicators": [{ "description": "업무 목적·중요도에 따라 네트워크를 영역별로 분리하고 접근통제를 적용하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「업무 목적 및 중요도에 따라 네트워크를 영역별(DMZ, 서버팜, DB존, 개발존 등)로 분리하고 접근통제를 적용한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준 "…**네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제**…" 구절.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.1-GL04 · 원거리 연결 전송구간 보호
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.1-GL04",
  "name": "원거리 연결 전송구간 보호",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["물리적으로 떨어진 IDC·지사·대리점 등과의 네트워크 연결 시 전송구간 보호대책을 마련한다."],
  "compliance_indicators": [{ "description": "원거리 네트워크 연결 시 전송구간 보호대책을 마련하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「물리적으로 떨어진 IDC·지사·대리점 등과의 네트워크 연결 시 전송구간 보호대책을 마련한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.1 인증기준의 접근통제 확장, 즉 **원거리 연결 구간 보호** 규정 여부를 본다.
- ISMS-P 2.6.1 네트워크 접근 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

## 2.6.3 응용프로그램 접근

### R-2.6.3-01 · Ingress 인증 적용 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.3-01",
  "name": "Ingress 인증 적용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "auth_annotations": ["nginx.ingress.kubernetes.io/auth-type", "nginx.ingress.kubernetes.io/auth-url", "alb.ingress.kubernetes.io/auth-type", "traefik.ingress.kubernetes.io/auth-type"],
  "compliance_indicators": [
    { "field": "all_ingresses_have_auth", "op": "==", "value": true, "description": "Pod에 연결된 모든 Ingress에 인증 설정 적용됨" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Pod에 연결된 모든 Ingress에 인증(auth) 설정이 적용됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_ingresses` / 컬럼: `ingress_class`, `rules`(JSONB), `tls`(JSONB) 및 annotation
- **JSON 필드 ↔ DB 매핑** — `all_ingresses_have_auth`는 **파생값**. 계산 과정: 각 Ingress의 annotation에 `auth_annotations` 4종(nginx/alb/traefik auth-type·auth-url) 중 하나라도 있는지 확인 → 모든 Ingress가 인증 설정을 가지면 `True`.
- 판정 기준: `all_ingresses_have_auth == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.3 인증기준 "…**응용프로그램 접근권한을 제한**…" 중 진입점(Ingress)의 인증 적용 여부를 본다.
- ISMS-P 2.6.3 응용프로그램 접근 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조·제6조

### R-2.6.3-02 · 내부 Service mTLS 강제 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.3-02",
  "name": "내부 Service mTLS 강제 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "acceptable_mtls_modes": ["STRICT"],
  "compliance_indicators": [
    { "field": "istio_injection_enabled", "op": "==", "value": true, "description": "namespace에 istio sidecar 자동 주입 활성" },
    { "field": "effective_mtls_mode", "op": "==", "value": "STRICT", "description": "namespace 또는 mesh-wide PeerAuthentication mtls.mode=STRICT 적용" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 내부 서비스 통신에 Istio sidecar 주입과 mTLS STRICT가 적용됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_namespaces` / 컬럼: `namespace` (TEXT). ⚠️ **라벨 컬럼 미적재**(istio-injection 라벨 등)로 namespace 라벨 기반 판정이 현 구조상 어려워 **사실상 미준수로 떨어짐**.
- **JSON 필드 ↔ DB 매핑** — `istio_injection_enabled`(namespace `istio-injection=enabled` 라벨), `effective_mtls_mode`(PeerAuthentication mtls.mode) — 둘 다 라벨/CR 적재 필요.
- 판정 기준: `istio_injection_enabled == True` AND `effective_mtls_mode == STRICT` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.3 인증기준의 접근 보호, 즉 내부 서비스 간 **상호 인증(mTLS) 강제** 여부를 본다.
- ISMS-P 2.6.3 응용프로그램 접근 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조·제6조

### R-2.6.3-GL01 · 응용프로그램 접근권한 제한
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.3-GL01",
  "name": "응용프로그램 접근권한 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["사용자별 업무 및 정보의 중요도에 따라 응용프로그램 접근권한을 제한한다."],
  "compliance_indicators": [{ "description": "사용자별 업무·정보 중요도에 따라 응용프로그램 접근권한을 제한하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「사용자별 업무 및 정보의 중요도에 따라 응용프로그램 접근권한을 제한한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.3 인증기준 "…**응용프로그램 접근권한을 제한**…" 구절.
- ISMS-P 2.6.3 응용프로그램 접근 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조·제6조

### R-2.6.3-GL02 · 표시제한 보호조치 기준 수립
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.3-GL02",
  "name": "표시제한 보호조치 기준 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["개인정보 및 중요정보의 표시제한 보호조치의 일관성을 확보할 수 있도록 관련 기준을 수립하여 적용한다."],
  "compliance_indicators": [{ "description": "개인정보·중요정보 표시제한 보호조치 기준을 수립·적용하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「개인정보 및 중요정보의 표시제한 보호조치의 일관성을 확보할 수 있도록 관련 기준을 수립하여 적용한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.3 인증기준 "…**중요정보 노출을 최소화**…기준을 수립…" 중 표시제한(마스킹) 기준 측면.
- ISMS-P 2.6.3 응용프로그램 접근 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조·제6조

### R-2.6.3-GL03 · 정보 노출 최소화
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.3-GL03",
  "name": "정보 노출 최소화",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["개인정보 및 중요정보의 불필요한 노출(조회, 화면표시, 인쇄, 다운로드 등)을 최소화하도록 응용프로그램을 구현·운영한다."],
  "compliance_indicators": [{ "description": "불필요한 정보 노출을 최소화하도록 응용프로그램을 구현·운영하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「개인정보 및 중요정보의 불필요한 노출(조회, 화면표시, 인쇄, 다운로드 등)을 최소화하도록 응용프로그램을 구현·운영한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.3 인증기준 "…**불필요한 정보 또는 중요정보 노출을 최소화**…" 구절.
- ISMS-P 2.6.3 응용프로그램 접근 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조·제6조

### R-2.6.3-GL04 · 세션 통제
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.3-GL04",
  "name": "세션 통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["동일 사용자의 동시 접속 세션 수를 제한하고 일정시간 미사용 시 세션을 자동 차단한다."],
  "compliance_indicators": [{ "description": "동시 세션 제한 및 미사용 세션 자동 차단을 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「동일 사용자의 동시 접속 세션 수를 제한하고 일정시간 미사용 시 세션을 자동 차단한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.3 인증기준의 접근 통제 운영, 즉 **세션(동시 접속·미사용 차단)** 통제 규정 여부를 본다.
- ISMS-P 2.6.3 응용프로그램 접근 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조·제6조

## 2.6.7 인터넷 접속 통제

### F-2.6.7-01 · Pod egress 통제 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.6.7-01",
  "name": "Pod egress 통제 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Pod + NetworkPolicy",
    "required_data": ["cluster_pods", "cluster_network_policies"],
    "condition": { "operator": "egress_policy_applied" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.6.7", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "운영 서버에서 외부 인터넷 자유 접속", "match": "direct" }],
    "additional_review_items": ["K8s 외 VPC NAT Gateway 화이트리스트 적용 여부", "프록시 서버를 통한 외부 접속 통제", "발견된 Pod가 개인정보 처리 시스템인지"],
    "manual_check_areas": ["외부 접속 화이트리스트 정책", "프록시 서버 운영 현황", "VPC 라우팅 정책"],
    "automation_coverage": { "percentage": 40, "covered": "K8s NetworkPolicy 기반 통제", "not_covered": "VPC NAT, 프록시 등 외부 통제" },
    "alternative_controls": ["VPC NAT Gateway 화이트리스트", "프록시 서버(Squid 등)", "Cilium FQDN policy", "AWS Network Firewall"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- Pod 아웃바운드가 egress 정책으로 통제되는지 집계한 뒤, VPC NAT·프록시 등 외부 통제는 사람이 검토.
- **집계 대상 테이블** — `cluster_pods`, `cluster_network_policies`
- **사람 검토 영역** — 외부 접속 화이트리스트 정책, 프록시 서버 운영 현황, VPC 라우팅 정책
- **자동화 커버리지** — 40% (K8s NetworkPolicy 기반 통제만)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - VPC NAT Gateway 화이트리스트 / 프록시 서버(Squid 등) / Cilium FQDN policy / AWS Network Firewall로 아웃바운드가 통제됨
- **인증기준의 어느 부분을 보는가** — 2.6.7 인증기준의 **인터넷 접속 통제**가 Pod egress 수준에서 적용되는지를 본다.
- ISMS-P 2.6.7 인터넷 접속 통제 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### F-2.6.7-02 · 실제 외부 도메인 접속 관찰 (eBPF)
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.6.7-02",
  "name": "실제 외부 도메인 접속 관찰 (eBPF)",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "eBPF DNS queries",
    "required_data": ["ebpf_dns_queries", "cluster_pods"],
    "condition": { "operator": "external_domain_traffic_report", "time_window": "24h" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.6.7", "match_strength": "supportive" }],
    "additional_review_items": ["화이트리스트와 실제 접속 패턴 일치 여부", "의심 도메인 접속이 있는가", "개인정보 처리 Pod의 외부 접속 패턴 검토"],
    "manual_check_areas": ["외부 접속 화이트리스트", "DNS 로그 분석 기록"],
    "automation_coverage": { "percentage": 80, "covered": "실제 통신 패턴 관찰", "not_covered": "통제 정책 자체" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- eBPF DNS 쿼리로 실제 외부 도메인 접속 패턴을 24시간 관찰한 뒤, 화이트리스트 일치·의심 도메인은 사람이 검토.
- **집계 대상 테이블** — `ebpf_dns_queries`, `cluster_pods`
- **사람 검토 영역** — 외부 접속 화이트리스트, DNS 로그 분석 기록
- **자동화 커버리지** — 80% (실제 통신 패턴 관찰), 통제 정책 자체는 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 관찰된 실제 외부 접속이 외부 접속 화이트리스트 범위 내이고 의심 도메인이 없음(DNS 로그 분석 기록으로 확인)
- **인증기준의 어느 부분을 보는가** — 2.6.7 인증기준의 **인터넷 접속 통제의 실효성**(실제 외부 접속이 정책과 일치하는지)을 본다.
- ISMS-P 2.6.7 인터넷 접속 통제 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.7-01 · egress NetworkPolicy 미적용
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.7-01",
  "name": "egress NetworkPolicy 미적용",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "has_egress_policy", "op": "==", "value": true, "description": "Pod에 매칭되는 Egress NetworkPolicy 존재 — 아웃바운드 트래픽 통제 적용" },
    { "field": "egress_default_deny_exists", "op": "==", "value": true, "description": "namespace에 Egress default-deny NetworkPolicy 존재" }
  ],
  "exception_check": { "annotation": "security-exception/egress-justification", "system_namespaces": ["kube-system", "kube-node-lease", "amazon-cloudwatch"] },
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Pod에 egress 통제 정책과 namespace egress default-deny가 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_network_policies` / 컬럼: `pod_selector`, `policy_types`, `ingress_rules`, `egress_rules` (JSONB)
- **JSON 필드 ↔ DB 매핑** — 두 필드 모두 **파생값**. ① `has_egress_policy`: 대상 Pod 라벨에 매칭되며 `policy_types`에 Egress가 포함된 정책 존재 여부 → ② `egress_default_deny_exists`: 해당 ns에 `pod_selector={}`+Egress이고 `egress_rules`가 비어 있는 정책 존재 여부.
- 판정 기준: `has_egress_policy == True` AND `egress_default_deny_exists == True`(예외 제외) ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.6.7 인증기준의 **인터넷(아웃바운드) 접속 통제**가 정책으로 적용됐는지를 본다.
- ISMS-P 2.6.7 인터넷 접속 통제 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.7-GL01 · 인터넷 접속 통제 정책 수립
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.7-GL01",
  "name": "인터넷 접속 통제 정책 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["업무용 단말기 등에서 인터넷 접속 시 정보유출 등 보안사고를 예방하기 위한 인터넷 접속 통제 정책을 수립·이행한다."],
  "compliance_indicators": [{ "description": "인터넷 접속 통제 정책을 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.7", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「업무용 단말기 등에서 인터넷 접속 시 정보유출 등 보안사고를 예방하기 위한 인터넷 접속 통제 정책을 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.7 인증기준 "…**인터넷 접속 통제 정책을 수립·이행**…" 구절.
- ISMS-P 2.6.7 인터넷 접속 통제 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.7-GL02 · 주요 시스템 외부 인터넷 접속 통제
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.7-GL02",
  "name": "주요 시스템 외부 인터넷 접속 통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["주요 정보시스템(DB 서버 등)에서 불필요한 외부 인터넷 접속을 통제한다."],
  "compliance_indicators": [{ "description": "주요 정보시스템의 불필요한 외부 인터넷 접속을 통제하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.7", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「주요 정보시스템(DB 서버 등)에서 불필요한 외부 인터넷 접속을 통제한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.7 인증기준의 적용 범위, 즉 **주요 시스템(DB 등)의 외부 접속 통제** 규정 여부를 본다.
- ISMS-P 2.6.7 인터넷 접속 통제 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

### R-2.6.7-GL03 · 인터넷망 차단 의무 이행
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.6.7-GL03",
  "name": "인터넷망 차단 의무 이행",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["관련 법령에 따라 인터넷망 차단 의무가 부과된 경우 대상자를 식별하여 안전한 방식으로 인터넷망 차단 조치를 적용한다."],
  "compliance_indicators": [{ "description": "법령상 인터넷망 차단 의무 대상자를 식별하고 차단 조치를 적용하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.6.7", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「관련 법령에 따라 인터넷망 차단 의무가 부과된 경우 대상자를 식별하여 안전한 방식으로 인터넷망 차단 조치를 적용한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.6.7 인증기준의 법적 요구 이행, 즉 **인터넷망 차단 의무 대상 식별·적용** 규정 여부를 본다.
- ISMS-P 2.6.7 인터넷 접속 통제 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다."
- 법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조

## 2.7.1 암호정책 적용

### F-2.7.1-01 · Ingress TLS 적용 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.7.1-01",
  "name": "Ingress TLS 적용 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Ingress",
    "required_data": ["cluster_ingresses"],
    "condition": { "operator": "field_non_empty", "field": "spec.tls" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.7.1", "match_strength": "direct" }, { "framework": "개인정보보호법", "item": "안전성 확보조치 - 전송 시 암호화", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "외부 송수신 시 평문 전송", "match": "direct" }],
    "additional_review_items": ["미설정 Ingress가 외부 LB(CloudFront 등)에서 TLS 종료 후 평문 전달 구조인가", "그렇다면 클러스터 내 통신 보호 별도 통제 필요(mTLS 등)", "진짜 HTTP 평문이라면 즉시 시정"],
    "manual_check_areas": ["저장 데이터 암호화 적용"],
    "automation_coverage": { "percentage": 20, "covered": "Ingress 레벨 TLS", "not_covered": "Secret etcd 암호화, ConfigMap 평문, KMS 키 관리" },
    "alternative_controls": ["CloudFront/외부 LB TLS", "외부 인증서 관리"],
    "k8s_only_check": true,
    "deferred": false,
    "deferred_reason": "AWS API 미접근으로 EKS describe/KMS/ALB 점검 불가"
  }
}
```

- Ingress의 `spec.tls` 설정 유무를 집계한 뒤, 외부 LB TLS 종료 구조·저장 암호화는 사람이 검토.
- **집계 대상 테이블** — `cluster_ingresses`
- **사람 검토 영역** — 저장 데이터 암호화 적용 (외부 LB TLS 종료 구조 여부)
- **자동화 커버리지** — 20% (Ingress 레벨 TLS만), Secret etcd·ConfigMap·KMS는 별도 룰/수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 외부 LB(CloudFront/ALB)에서 TLS 종료 후 클러스터 내부는 mTLS로 보호되는 구조임
  - 저장 데이터 암호화(Secret etcd·KMS)가 별도로 적용돼 있음
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준의 **전송 시 암호화**가 외부 진입점(Ingress)에 적용됐는지를 본다.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-01 · Secret etcd 암호화 점검
⚙️ 클라우드 실측(제출 증적 VLM 추출 → 구조 매칭)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-01",
  "name": "Secret etcd 암호화 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "manual_evidence_spec": {
    "title": "EKS 클러스터 Secret 암호화 설정 캡처",
    "description": "etcd에 저장되는 Kubernetes Secret이 KMS로 envelope 암호화되어 있음을 증명",
    "acceptable_formats": ["png", "jpg", "pdf", "json", "txt"],
    "max_age_days": 365,
    "recommended_evidence_sources": ["AWS Console → EKS → 대상 클러스터 → Overview 탭 → 'Secrets encryption' 섹션 캡처", "CLI 출력 캡처/파일: aws eks describe-cluster --name <CLUSTER명> --query 'cluster.encryptionConfig'"],
    "required_content": [
      { "field": "encryption_resources", "description": "암호화 대상에 'secrets' 포함 여부", "expected_pattern": "['secrets']" },
      { "field": "kms_key_arn", "description": "사용 중인 KMS 키 ARN", "expected_pattern": "^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$" },
      { "field": "cluster_name", "description": "EKS 클러스터명 (룰 평가 대상 클러스터와 일치 확인)" }
    ]
  },
  "compliance_indicators": [
    { "field": "evidence.encryption_resources", "op": "contains", "value": "secrets", "description": "secrets 리소스가 암호화 대상에 포함" },
    { "field": "evidence.kms_key_arn", "op": "matches_regex", "value": "^arn:aws:kms:", "description": "유효한 KMS 키 ARN 존재" }
  ],
  "judgment_logic": { "type": "manual_evidence_match", "method": "vlm_extract_then_structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- EKS Secret이 KMS envelope 암호화로 etcd에 저장되는지, 제출 증적(콘솔 캡처/CLI 출력)을 VLM으로 추출해 판정한다.
- **가져오는 곳** — `cluster_*` 스냅샷 테이블 아님 / **제출 증적**(EKS Overview 'Secrets encryption' 캡처 또는 `aws eks describe-cluster ... encryptionConfig` 출력)에서 VLM 추출.
- **추출 항목 ↔ 비교** — `evidence.encryption_resources`(=secrets 포함), `evidence.kms_key_arn`(KMS ARN 정규식)
- 판정 기준: encryption_resources에 `secrets` 포함 AND kms_key_arn이 `^arn:aws:kms:` 매칭 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준의 **저장 시 암호화**가 Secret(etcd)에 적용됐는지를 본다.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-02 · ConfigMap 평문 비밀값 점검
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-02",
  "name": "ConfigMap 평문 비밀값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "secret_patterns": [
    { "name": "password", "regex": "(?i)(password|passwd|pwd)\\s*[:=]\\s*[\"']?[\\w@!#$%^&*-]{6,}" },
    { "name": "aws_access_key", "regex": "AKIA[0-9A-Z]{16}" },
    { "name": "private_key", "regex": "-----BEGIN [A-Z ]*PRIVATE KEY-----" },
    { "name": "secret_token", "regex": "(?i)(secret|token|api[_-]?key)\\s*[:=]\\s*[\"']?[\\w\\-\\.]{16,}" },
    { "name": "jwt", "regex": "eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]+" }
  ],
  "compliance_indicators": [
    { "field": "configmap_has_secrets", "op": "==", "value": false, "description": "Pod가 참조하는 ConfigMap에 평문 비밀값 없음" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Pod가 참조하는 ConfigMap에 평문 비밀값(비번·키·토큰·JWT)이 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_configmaps` / 컬럼: `name`, `namespace`(및 data)
- **JSON 필드 ↔ DB 매핑** — `configmap_has_secrets`는 **파생값**. 계산 과정: ConfigMap data 값들을 `secret_patterns` 5종 정규식(password·AKIA·PRIVATE KEY·secret/token·JWT)과 대조 → 하나라도 매칭되면 `True`.
- 판정 기준: `configmap_has_secrets == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준의 **비밀정보 평문 저장 금지(암호화 대상 보호)**가 지켜지는지를 본다.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-03 · 전송구간 TLS 적용 점검
⚙️ 클라우드 실측(K8s API + 제출 증적 하이브리드)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-03",
  "name": "전송구간 TLS 적용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "k8s_native_check": {
    "compliance_indicators": [
      { "field": "all_external_ingresses_have_tls", "op": "==", "value": true, "source": "k8s", "description": "외부 노출 Ingress 모두 .spec.tls 설정 존재" }
    ]
  },
  "manual_evidence_spec": {
    "title": "ALB Listener SSL 정책 캡처",
    "description": "외부 ALB의 HTTPS Listener가 TLS 1.2 이상의 승인된 SSL 정책을 사용함을 증명",
    "approved_alb_ssl_policies": ["ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", "ELBSecurityPolicy-FS-1-2-Res-2020-10"],
    "tls_min_version": "TLSv1.2",
    "required_content": [
      { "field": "alb_arn_or_name", "description": "대상 ALB의 ARN 또는 이름" },
      { "field": "listener_protocol", "description": "Listener 프로토콜", "expected_pattern": "^HTTPS$" },
      { "field": "ssl_policy", "description": "사용 중인 SSL 정책명" }
    ]
  },
  "compliance_indicators": [
    { "field": "all_external_ingresses_have_tls", "op": "==", "value": true, "source": "k8s", "description": "Ingress .spec.tls 설정 존재" },
    { "field": "evidence.listener_protocol", "op": "==", "value": "HTTPS", "source": "manual", "description": "ALB Listener HTTPS 사용" },
    { "field": "evidence.ssl_policy", "op": "in_approved_list", "value": "approved_alb_ssl_policies", "source": "manual", "description": "승인된 SSL 정책(TLS 1.2+) 사용" }
  ],
  "judgment_logic": { "type": "hybrid_match", "method": "k8s_structured_match + vlm_extract_then_structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 외부 Ingress의 TLS 설정(K8s)과 ALB HTTPS Listener의 SSL 정책(증적)을 함께 보는 하이브리드 판정.
- **가져오는 곳** — (K8s) 테이블 `cluster_ingresses`의 `tls`(JSONB) + (증적) ALB Listener SSL 정책 캡처/`aws elbv2 describe-listeners` 출력.
- **JSON 필드 ↔ DB 매핑** — `all_external_ingresses_have_tls`는 `cluster_ingresses`에서 모든 외부 Ingress가 `tls` 설정을 갖는지 파생; `evidence.listener_protocol`/`evidence.ssl_policy`는 제출 증적에서 VLM 추출.
- 판정 기준: 모든 외부 Ingress TLS 설정 AND ALB Listener=HTTPS AND ssl_policy가 승인 목록(TLS1.2+) 포함 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준의 **전송 시 암호화(암호 강도 포함)**가 외부 구간 전체에 적용됐는지를 본다.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-04 · KMS 키 로테이션 및 상태 점검
⚙️ 클라우드 실측(제출 증적 VLM 추출 → 구조 매칭)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-04",
  "name": "KMS 키 로테이션 및 상태 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "manual_evidence_spec": {
    "title": "KMS Customer Managed Key 로테이션·상태 캡처",
    "description": "EKS Secret 암호화에 사용하는 KMS 키의 활성 상태, 자동 로테이션 활성, 승인 알고리즘 사용을 증명",
    "max_age_days": 90,
    "recommended_evidence_sources": ["AWS Console → KMS → Customer managed keys → 대상 키 → General configuration/Key rotation 탭 캡처", "aws kms describe-key --key-id <KEY_ID>", "aws kms get-key-rotation-status --key-id <KEY_ID>"],
    "approved_key_specs": ["SYMMETRIC_DEFAULT", "RSA_2048", "RSA_3072", "RSA_4096"],
    "required_content": [
      { "field": "key_arn", "description": "KMS 키 ARN" },
      { "field": "key_state", "description": "키 상태 (Enabled/Disabled/PendingDeletion 등)" },
      { "field": "key_enabled", "description": "키 사용 가능 여부 (Boolean)" },
      { "field": "key_spec", "description": "키 스펙 (알고리즘)" },
      { "field": "key_rotation_enabled", "description": "자동 키 로테이션 활성 여부 (Boolean)" }
    ]
  },
  "compliance_indicators": [
    { "field": "evidence.key_state", "op": "==", "value": "Enabled", "description": "KMS 키 활성 상태" },
    { "field": "evidence.key_enabled", "op": "==", "value": true, "description": "KMS 키 사용 가능" },
    { "field": "evidence.key_rotation_enabled", "op": "==", "value": true, "description": "자동 키 로테이션 활성 (연 1회)" },
    { "field": "evidence.key_spec", "op": "in_approved_list", "value": "approved_key_specs", "description": "KISA 안내서 기준 알고리즘 사용 (AES-256 또는 RSA-2048 이상)" }
  ],
  "judgment_logic": { "type": "manual_evidence_match", "method": "vlm_extract_then_structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 암호화에 쓰는 KMS 키가 활성·자동 로테이션·승인 알고리즘인지, 제출 증적을 VLM으로 추출해 판정한다.
- **가져오는 곳** — `cluster_*` 스냅샷 테이블 아님 / **제출 증적**(KMS 콘솔 캡처, `aws kms describe-key`·`get-key-rotation-status` 출력)에서 VLM 추출.
- **추출 항목 ↔ 비교** — `evidence.key_state`, `key_enabled`, `key_rotation_enabled`, `key_spec`
- 판정 기준: state=Enabled, enabled=true, rotation_enabled=true, key_spec이 승인 목록(SYMMETRIC_DEFAULT/RSA_2048+) 포함 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준의 **암호 강도·키 관리(로테이션)** 측면을 본다.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-GL01 · 암호정책 수립
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-GL01",
  "name": "암호정책 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 등이 포함된 암호정책을 수립한다."],
  "compliance_indicators": [{ "description": "암호화 대상·강도·사용 정책을 포함한 암호정책을 수립하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.7.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 등이 포함된 암호정책을 수립한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준 "…**암호화 대상, 암호 강도, 암호 사용 정책을 수립**…" 구절.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-GL02 · 저장·전송·전달 시 암호화
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-GL02",
  "name": "저장·전송·전달 시 암호화",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["암호정책에 따라 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 수행한다."],
  "compliance_indicators": [{ "description": "개인정보·주요정보의 저장·전송·전달 시 암호화를 수행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.7.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「암호정책에 따라 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 수행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준 "…**저장·전송·전달 시 암호화를 적용**…" 구절.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

### R-2.7.1-GL03 · 암호키 관리 절차
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.7.1-GL03",
  "name": "암호키 관리 절차",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["암호키의 생성·이용·보관·폐기·변경(로테이션) 등 키 관리 절차를 수립·이행한다."],
  "compliance_indicators": [{ "description": "암호키 생성·보관·폐기·변경 등 키 관리 절차를 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.7.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「암호키의 생성·이용·보관·폐기·변경(로테이션) 등 키 관리 절차를 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.7.1 인증기준의 **암호 사용 정책** 중 키 생애주기 관리 절차를 본다.
- ISMS-P 2.7.1 암호정책 적용 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다."
- 법적 근거: 개인정보 보호법 제24조의2·제29조, 개인정보의 안전성 확보조치 기준 제7조

## 2.8.3 시험과 운영 환경 분리

### F-2.8.3-01 · 환경 라벨 적용 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.8.3-01",
  "name": "환경 라벨 적용 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "additional_evidence",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": ["cluster_pods.labels"],
    "condition": { "operator": "label_value_in", "field": "labels.env", "values": ["prod", "stg", "dev", "test"] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.8.3", "match_strength": "indirect" }],
    "additional_review_items": ["회사가 env 라벨로 환경 구분 정책인가", "별도 클러스터/VPC로 환경 분리되어 있는가", "namespace 네이밍 컨벤션으로 식별되는가"],
    "manual_check_areas": ["클러스터/VPC 분리 설계"],
    "automation_coverage": { "percentage": 0, "covered": "K8s 라벨 컨벤션 채택 시", "not_covered": "클러스터/VPC 분리 점검" },
    "alternative_controls": ["별도 클러스터", "별도 VPC", "namespace 네이밍 컨벤션"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- Pod의 env 라벨(prod/stg/dev/test) 적용 현황을 집계한 뒤, 클러스터/VPC 분리 설계는 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.labels`
- **사람 검토 영역** — 클러스터/VPC 분리 설계
- **자동화 커버리지** — 0% (라벨 컨벤션 채택 시에만 의미), 분리 점검은 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - env 라벨이 없어도 별도 클러스터/별도 VPC/namespace 네이밍 컨벤션으로 환경이 식별·분리됨
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준의 **환경 분리** 전제(환경 식별 가능 여부)를 본다.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### F-2.8.3-02 · 환경 혼재 namespace 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.8.3-02",
  "name": "환경 혼재 namespace 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod (cluster-wide)",
    "required_data": ["cluster_pods.labels", "cluster_namespaces"],
    "condition": { "operator": "namespace_env_homogeneous" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.8.3", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "동일 시스템에서 운영/개발 병행", "match": "direct" }],
    "additional_review_items": ["회사 환경 분리 정책이 namespace 단위인가 cluster 단위인가", "namespace 분리 정책이면 결함 가능", "cluster 분리 정책이면 namespace 내 혼재는 무관"],
    "automation_coverage": { "percentage": 100, "covered": "env 라벨 부여 시 namespace 내 혼재 점검", "not_covered": "라벨 미부여 시 점검 불가" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 한 namespace 안에 서로 다른 env가 섞여 있는지(혼재) 집계한 뒤, 분리 정책 단위(ns/cluster)는 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.labels`, `cluster_namespaces`
- **사람 검토 영역** — 회사 환경 분리 정책 단위(namespace vs cluster)
- **자동화 커버리지** — 100% (env 라벨이 있을 때만), 라벨 미부여 시 점검 불가
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 환경 분리 정책이 cluster/VPC 단위이고 그 수준에서 분리됨 → namespace 내 혼재는 무관 (단, ns 단위 분리 정책이면 결함)
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준의 **개발/시험과 운영 분리**(동일 namespace 혼재 여부)를 본다.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.8.3-01 · 워크로드 env 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.8.3-01",
  "name": "워크로드 env 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "workload.metadata.labels.env", "op": "in", "value": ["production", "staging", "development", "test"], "description": "워크로드에 유효한 환경 구분(env) 라벨 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 워크로드에 유효한 env 라벨이 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `labels` (JSONB)
- **JSON 필드 ↔ DB 매핑** — `workload.metadata.labels.env` = `cluster_pods.labels ->> 'env'`.
- 판정 기준: `env in [production·staging·development·test]` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준의 환경 분리 전제, 즉 **워크로드 환경 식별** 가능 여부를 본다.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.8.3-02 · namespace 내 prod/dev 워크로드 혼재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.8.3-02",
  "name": "namespace 내 prod/dev 워크로드 혼재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "conflicting_env_pairs": [["production", "development"], ["production", "test"], ["production", "staging"]],
  "compliance_indicators": [
    { "field": "namespace_has_mixed_envs", "op": "==", "value": false, "description": "동일 namespace 내 운영(production)과 개발/시험 워크로드 미혼재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 동일 namespace에 운영과 개발/시험 워크로드가 섞여 있는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_workloads` / 컬럼: `kind`, `selector`, `template_labels`(JSONB), `containers`(JSONB)
- **JSON 필드 ↔ DB 매핑** — `namespace_has_mixed_envs`는 **파생값**. 계산 과정: namespace별로 워크로드의 `template_labels.env` 값 집합을 모아 `conflicting_env_pairs`(production↔development/test/staging) 조합이 동시에 존재하면 `True`.
- 판정 기준: `namespace_has_mixed_envs == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준 "…**원칙적으로 분리**…" 중 운영-개발 혼재 금지를 본다.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.8.3-03 · prod Secret이 dev에서 참조
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.8.3-03",
  "name": "prod Secret이 dev에서 참조",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "prod_secret_used_by_dev", "op": "==", "value": false, "description": "운영(production) 라벨 Secret이 개발/시험 워크로드에서 참조되지 않음" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 운영용 Secret이 개발/시험 워크로드에서 참조되는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_secrets`(`name`, `namespace`, `type`), `cluster_workloads`(참조 관계)
- **JSON 필드 ↔ DB 매핑** — `prod_secret_used_by_dev`는 **파생값**. 계산 과정: production 라벨 Secret을 식별 → 이를 volume/env로 참조하는 워크로드 중 env가 development/test인 것이 있으면 `True`.
- 판정 기준: `prod_secret_used_by_dev == False` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준의 **운영-개발 경계 침범 차단**(운영 비밀정보가 개발로 흘러가는지)을 본다.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.8.3-GL01 · 개발·시험과 운영 환경 분리 원칙
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.8.3-GL01",
  "name": "개발·시험과 운영 환경 분리 원칙",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["개발 및 시험 시스템을 운영시스템과 원칙적으로 분리한다."],
  "compliance_indicators": [{ "description": "개발·시험 시스템을 운영시스템과 원칙적으로 분리하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.8.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「개발 및 시험 시스템을 운영시스템과 원칙적으로 분리한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준 "…**원칙적으로 분리**…" 구절.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.8.3-GL02 · 분리 곤란 시 보완통제
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.8.3-GL02",
  "name": "분리 곤란 시 보완통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["불가피하게 개발과 운영 환경의 분리가 어려운 경우 상호검토, 상급자 모니터링, 변경 승인, 책임추적성 확보 등의 보안대책을 마련한다."],
  "compliance_indicators": [{ "description": "환경 분리가 어려운 경우 상호검토·모니터링·변경승인·책임추적성 등 보완통제를 마련하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.8.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「불가피하게 개발과 운영 환경의 분리가 어려운 경우 상호검토, 상급자 모니터링, 변경 승인, 책임추적성 확보 등의 보안대책을 마련한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.8.3 인증기준의 예외 처리, 즉 **분리 곤란 시 보완통제** 규정 여부를 본다.
- ISMS-P 2.8.3 시험과 운영 환경 분리 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

## 2.9.1 변경관리

### R-2.9.1-01 · change-cause annotation 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.9.1-01",
  "name": "change-cause annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "deployment.metadata.annotations.kubernetes.io/change-cause", "op": "!=", "value": null, "description": "Deployment에 change-cause annotation 존재 — 변경 사유 기록됨" },
    { "field": "latest_replicaset_has_change_cause", "op": "==", "value": true, "description": "최신 ReplicaSet에 change-cause annotation 전파됨" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Deployment/최신 ReplicaSet에 변경 사유(change-cause) annotation이 기록됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_workloads` / 컬럼: `kind`, `selector`, `template_labels`(JSONB), `containers`(JSONB) 및 annotation
- **JSON 필드 ↔ DB 매핑** — `deployment.metadata.annotations.kubernetes.io/change-cause`(존재 여부); `latest_replicaset_has_change_cause`는 **파생값**(Deployment의 최신 ReplicaSet에 동일 annotation이 전파됐는지).
- 판정 기준: change-cause != null AND 최신 RS 전파됨 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.9.1 인증기준 "…변경에 대한 절차를 수립하여 **변경 이력을 관리**…" 중 변경 사유 기록 여부를 본다.
- ISMS-P 2.9.1 변경관리 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.9.1-02 · revisionHistoryLimit=0 (롤백 불가)
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.9.1-02",
  "name": "revisionHistoryLimit=0 (롤백 불가)",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "deployment.spec.revisionHistoryLimit", "op": ">", "value": 0, "description": "revisionHistoryLimit > 0 — 이전 ReplicaSet 보존으로 롤백 가능" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- Deployment가 이전 리비전을 보존(revisionHistoryLimit>0)해 롤백이 가능한지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_workloads` / 컬럼: `kind`, `containers`(JSONB) 등 워크로드 스펙
- **JSON 필드 ↔ DB 매핑** — `deployment.spec.revisionHistoryLimit` = 워크로드 스펙의 해당 값.
- 판정 기준: `revisionHistoryLimit > 0` ⇒ 준수(롤백 가능)
- **인증기준의 어느 부분을 보는가** — 2.9.1 인증기준의 변경 안전성, 즉 **변경 실패 시 복구(롤백) 가능성**을 본다.
- ISMS-P 2.9.1 변경관리 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.9.1-GL01 · 변경 절차 및 이력 관리
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.9.1-GL01",
  "name": "변경 절차 및 이력 관리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정보시스템 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리한다."],
  "compliance_indicators": [{ "description": "정보시스템 변경 절차를 수립하고 변경 이력을 관리하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.9.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「정보시스템 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.9.1 인증기준 "…**절차를 수립하여 변경 이력을 관리**…" 구절.
- ISMS-P 2.9.1 변경관리 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

### R-2.9.1-GL02 · 변경 전 영향 분석
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.9.1-GL02",
  "name": "변경 전 영향 분석",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["정보시스템 관련 자산 변경을 수행하기 전에 성능 및 보안에 미치는 영향을 분석한다."],
  "compliance_indicators": [{ "description": "변경 전 시스템에 미치는 성능·보안 영향을 분석하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.9.1", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「정보시스템 관련 자산 변경을 수행하기 전에 성능 및 보안에 미치는 영향을 분석한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.9.1 인증기준 "…**변경 전 시스템에 미치는 영향을 분석**…" 구절.
- ISMS-P 2.9.1 변경관리 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다."
- 법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조

## 2.10.2 클라우드 보안

### R-2.10.2-08 · Namespace Pod Security Admission 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.2-08",
  "name": "Namespace Pod Security Admission 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "psa_levels": ["privileged", "baseline", "restricted"],
  "compliance_indicators": [
    { "field": "namespace.metadata.labels.pod-security.kubernetes.io/enforce", "op": "in", "value": ["baseline", "restricted"], "description": "PSA enforce 라벨이 baseline 또는 restricted로 설정됨" },
    { "field": "namespace.metadata.labels.pod-security.kubernetes.io/audit", "op": "in", "value": ["baseline", "restricted"], "description": "PSA audit 라벨이 baseline 또는 restricted로 설정됨" }
  ],
  "exception_check": { "annotation": "psa-exception/justification", "system_namespaces": ["kube-system", "kube-node-lease", "kube-public"] },
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- namespace에 Pod Security Admission(enforce/audit) 라벨이 baseline/restricted로 설정됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_namespaces` / 컬럼: `namespace` (TEXT). ⚠️ **라벨 컬럼 미적재**로 PSA 라벨 판정이 현 구조상 어려워 **사실상 미준수로 떨어짐**.
- **JSON 필드 ↔ DB 매핑** — `namespace.metadata.labels.pod-security.kubernetes.io/enforce`, `.../audit` — namespace 라벨 적재 필요.
- 판정 기준: enforce·audit 라벨 모두 `in [baseline·restricted]`(예외 제외) ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.2 인증기준 "…클라우드 서비스 유형에 따른 **보안대책을 수립·이행**…" 중 K8s(PaaS) 워크로드 보안 표준(PSA) 적용 여부를 본다.
- ISMS-P 2.10.2 클라우드 보안 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다."

### R-2.10.2-GL01 · 클라우드 유형별 위험평가·대책
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.2-GL01",
  "name": "클라우드 유형별 위험평가·대책",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["클라우드 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고 이에 맞는 보안대책을 수립·이행한다."],
  "compliance_indicators": [{ "description": "클라우드 서비스 유형별 보안 위험을 평가하고 보안대책을 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「클라우드 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고 이에 맞는 보안대책을 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.2 인증기준 "…**서비스 유형에 따른 보안 위험을 평가하고…보안대책을 수립·이행**…" 구절.
- ISMS-P 2.10.2 클라우드 보안 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다."

### R-2.10.2-GL02 · 클라우드 관리자 권한 최소화·보호
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.2-GL02",
  "name": "클라우드 관리자 권한 최소화·보호",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["클라우드 서비스 관리자 권한을 역할에 따라 최소화하여 부여하고, 강화된 인증·암호화·접근통제·감사기록 등 보호대책을 적용한다."],
  "compliance_indicators": [{ "description": "클라우드 관리자 권한 최소 부여 및 강화 인증·감사기록 등 보호대책 적용을 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「클라우드 서비스 관리자 권한을 역할에 따라 최소화하여 부여하고, 강화된 인증·암호화·접근통제·감사기록 등 보호대책을 적용한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.2 인증기준의 **보안대책 수립·이행** 중 관리자 권한 최소화·보호 측면을 본다.
- ISMS-P 2.10.2 클라우드 보안 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다."

### R-2.10.2-GL03 · 클라우드 설정·운영 모니터링
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.2-GL03",
  "name": "클라우드 설정·운영 모니터링",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["클라우드 서비스의 보안 설정 변경·운영 현황 등을 모니터링하고 그 적절성을 정기적으로 검토한다."],
  "compliance_indicators": [{ "description": "클라우드 보안 설정·운영 현황을 모니터링하고 정기 검토하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.2", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「클라우드 서비스의 보안 설정 변경·운영 현황 등을 모니터링하고 그 적절성을 정기적으로 검토한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.2 인증기준의 보안대책 운영, 즉 **클라우드 설정·운영 모니터링·정기 검토** 측면을 본다.
- ISMS-P 2.10.2 클라우드 보안 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다."

## 2.10.3 공개서버 보안

### F-2.10.3-03 · NodePort 노출 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.3-03",
  "name": "NodePort 노출 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Service",
    "required_data": ["cluster_services"],
    "condition": { "operator": "field_equals", "field": "spec.type", "value": "NodePort" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.3", "match_strength": "indirect" }],
    "additional_review_items": ["발견된 NodePort가 의도된 공개인가", "VPC SG에서 노드의 NodePort 차단되어 있는가"],
    "manual_check_areas": ["NodePort 사용 정책", "VPC Security Group 설정"],
    "automation_coverage": { "percentage": 50, "covered": "NodePort Service 식별", "not_covered": "VPC SG 차단 여부" },
    "alternative_controls": ["VPC Security Group", "Network ACL"],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- NodePort 타입 서비스를 식별한 뒤, 의도된 공개인지·VPC SG 차단 여부는 사람이 검토.
- **집계 대상 테이블** — `cluster_services`
- **사람 검토 영역** — NodePort 사용 정책, VPC Security Group 설정
- **자동화 커버리지** — 50% (NodePort 식별), VPC SG 차단은 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - VPC Security Group/Network ACL에서 해당 NodePort가 외부로부터 차단됨
  - 의도된 공개로 NodePort 사용 정책상 승인·문서화됨
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **외부 공개 경로 통제**, 즉 의도치 않은 NodePort 노출 여부를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-01 · LoadBalancer source range 미설정
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-01",
  "name": "LoadBalancer source range 미설정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "service.spec.loadBalancerSourceRanges", "op": "!=", "value": null, "description": "loadBalancerSourceRanges 설정됨 — 접근 허용 IP 대역 제한" },
    { "field": "source_range_not_all_open", "op": "==", "value": true, "description": "0.0.0.0/0 전체 허용이 아닌 특정 IP 대역으로 제한됨" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- LoadBalancer 서비스가 접근 IP 대역을 제한하는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_services` / 컬럼: `name`, `type`, `cluster_ip`, `external_name`, `selector`·`ports`(JSONB), `external_ips`(JSONB)
- **JSON 필드 ↔ DB 매핑** — `service.spec.loadBalancerSourceRanges`(존재 여부); `source_range_not_all_open`은 **파생값**(설정된 대역이 `0.0.0.0/0`이 아닌지).
- 판정 기준: source range 설정됨 AND 전체개방(0.0.0.0/0) 아님 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **공개서버 접근통제**(허용 IP 제한)를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-02 · 공개 Ingress WAF annotation 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-02",
  "name": "공개 Ingress WAF annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "waf_annotations": ["alb.ingress.kubernetes.io/wafv2-acl-arn", "alb.ingress.kubernetes.io/waf-acl-id", "nginx.ingress.kubernetes.io/modsecurity-snippet"],
  "compliance_indicators": [
    { "field": "public_ingress_has_waf", "op": "==", "value": true, "description": "공개 Ingress에 WAF(AWS WAFv2 ACL 또는 ModSecurity) annotation 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 공개 Ingress에 WAF(AWS WAFv2/ModSecurity) annotation이 적용됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_ingresses` / 컬럼: `ingress_class`, `rules`(JSONB), `tls`(JSONB) 및 annotation
- **JSON 필드 ↔ DB 매핑** — `public_ingress_has_waf`는 **파생값**. 계산 과정: 공개 Ingress의 annotation에 `waf_annotations` 3종 중 하나가 있는지 확인.
- 판정 기준: `public_ingress_has_waf == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **강화된 보호대책**, 즉 공개 진입점 WAF 적용 여부를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-03 · NodePort Service 공개 의도 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-03",
  "name": "NodePort Service 공개 의도 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "nodeport_service.metadata.labels.exposure-intent", "op": "in", "value": ["public", "internal-only", "debug"], "description": "NodePort Service에 공개 의도 라벨(exposure-intent) 존재 — 의도적 노출임을 명시" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- NodePort 서비스에 공개 의도(exposure-intent) 라벨이 명시됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_services` / 컬럼: `name`, `type`, `selector`·`ports`(JSONB) 및 라벨
- **JSON 필드 ↔ DB 매핑** — `nodeport_service.metadata.labels.exposure-intent` 라벨 값.
- 판정 기준: `exposure-intent in [public·internal-only·debug]` ⇒ 준수(의도 명시)
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **공개 의도 관리**(우발적 노출과 구분)를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-04 · 공개 Ingress rate limit 미설정
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-04",
  "name": "공개 Ingress rate limit 미설정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "rate_limit_annotations": ["nginx.ingress.kubernetes.io/limit-rps", "nginx.ingress.kubernetes.io/limit-rpm", "nginx.ingress.kubernetes.io/limit-connections", "alb.ingress.kubernetes.io/actions.rate-limit"],
  "compliance_indicators": [
    { "field": "public_ingress_has_rate_limit", "op": "==", "value": true, "description": "공개 Ingress에 rate limit annotation 설정됨 — DDoS/과다요청 방어" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 공개 Ingress에 rate limit annotation이 설정됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_ingresses` / 컬럼: `ingress_class`, `rules`(JSONB), `tls`(JSONB) 및 annotation
- **JSON 필드 ↔ DB 매핑** — `public_ingress_has_rate_limit`는 **파생값**. 계산 과정: 공개 Ingress annotation에 `rate_limit_annotations` 4종(limit-rps/rpm/connections, alb rate-limit) 중 하나가 있는지 확인.
- 판정 기준: `public_ingress_has_rate_limit == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **강화된 보호대책**, 즉 공개 서버 과다요청/DDoS 방어를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-05 · LoadBalancer 공개 의도 라벨 부재
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-05",
  "name": "LoadBalancer 공개 의도 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "lb_service.metadata.labels.exposure-intent", "op": "in", "value": ["public", "internal-only"], "description": "LoadBalancer Service에 공개 의도 라벨(exposure-intent) 존재 — 외부 노출 의도 명시" },
    { "field": "lb_has_internal_annotation_or_public_label", "op": "==", "value": true, "description": "internal LB annotation 또는 public exposure-intent 라벨 중 하나 존재" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- LoadBalancer 서비스에 공개 의도가 명시(라벨 또는 internal annotation)됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_services` / 컬럼: `name`, `type`, `selector`·`ports`(JSONB) 및 라벨/annotation
- **JSON 필드 ↔ DB 매핑** — `lb_service.metadata.labels.exposure-intent`(라벨 값); `lb_has_internal_annotation_or_public_label`은 **파생값**(internal LB annotation 또는 public 라벨 중 하나 존재).
- 판정 기준: exposure-intent 라벨 `in [public·internal-only]` AND 둘 중 하나 존재 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **공개 의도 관리**(외부 노출 명시)를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-GL01 · 공개서버 분리·강화 보호대책
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-GL01",
  "name": "공개서버 분리·강화 보호대책",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["외부에 공개되는 서버는 내부 네트워크와 분리하고, 취약점 점검·접근통제·이상징후 모니터링 등 강화된 보호대책을 수립·이행한다."],
  "compliance_indicators": [{ "description": "공개서버를 내부망과 분리하고 강화된 보호대책을 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「외부에 공개되는 서버는 내부 네트워크와 분리하고, 취약점 점검·접근통제·이상징후 모니터링 등 강화된 보호대책을 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준 "…내부 네트워크와 분리하고…**강화된 보호대책을 수립·이행**…" 구절 전반.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-GL02 · 공개서버 게시 허가 절차
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-GL02",
  "name": "공개서버 게시 허가 절차",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["공개서버에 개인정보 및 중요정보를 게시·저장해야 하는 경우 책임자 승인 등 허가 및 게시 절차를 수립·이행한다."],
  "compliance_indicators": [{ "description": "공개서버 게시·저장 시 책임자 승인 등 허가·게시 절차를 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「공개서버에 개인정보 및 중요정보를 게시·저장해야 하는 경우 책임자 승인 등 허가 및 게시 절차를 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 운영 통제, 즉 **공개서버 게시·저장 허가 절차** 규정 여부를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

### R-2.10.3-GL03 · 중요정보 노출 점검·차단
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.3-GL03",
  "name": "중요정보 노출 점검·차단",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["조직의 중요정보가 웹사이트·웹서버를 통해 노출되는지 주기적으로 확인하고, 노출을 인지한 경우 즉시 차단 등의 조치를 취한다."],
  "compliance_indicators": [{ "description": "웹을 통한 중요정보 노출을 주기적으로 점검하고 인지 시 즉시 차단하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「조직의 중요정보가 웹사이트·웹서버를 통해 노출되는지 주기적으로 확인하고, 노출을 인지한 경우 즉시 차단 등의 조치를 취한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.3 인증기준의 **이상징후 모니터링·대응**, 즉 웹 노출 점검·즉시 차단 규정 여부를 본다.
- ISMS-P 2.10.3 공개서버 보안 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다."

## 2.10.5 정보전송 보안

### F-2.10.5-01 · 외부 공개 Ingress TLS 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.5-01",
  "name": "외부 공개 Ingress TLS 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Ingress",
    "required_data": ["cluster_ingresses"],
    "condition": { "operator": "field_non_empty", "field": "spec.tls", "scope": "external_only" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.5", "match_strength": "direct" }, { "framework": "개인정보보호법", "item": "안전성 확보조치 - 전송 시 암호화", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "HTTP 통신으로 개인정보 송수신", "match": "direct" }],
    "additional_review_items": ["미설정 Ingress가 개인정보/중요정보 송수신 경로인가", "외부 LB에서 TLS 종료 + 클러스터 내 mTLS 구조인가"],
    "manual_check_areas": ["송수신 인터페이스 목록", "개인정보 처리 시스템 흐름도"],
    "automation_coverage": { "percentage": 40, "covered": "K8s Ingress TLS", "not_covered": "mTLS, 외부 LB TLS" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 외부 노출 Ingress의 TLS 설정 현황을 집계한 뒤, 개인정보 송수신 경로 여부·mTLS 구조는 사람이 검토.
- **집계 대상 테이블** — `cluster_ingresses`
- **사람 검토 영역** — 송수신 인터페이스 목록, 개인정보 처리 시스템 흐름도
- **자동화 커버리지** — 40% (K8s Ingress TLS만), mTLS·외부 LB TLS는 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 외부 LB에서 TLS 종료 + 클러스터 내 mTLS 구조임
  - 해당 경로가 개인정보/중요정보 송수신 경로가 아님(송수신 인터페이스 목록으로 확인)
- **인증기준의 어느 부분을 보는가** — 2.10.5 인증기준 "…전송 중 보호를 위한 **기술적 대책 적용**…" 중 외부 전송 구간 TLS 적용을 본다.
- ISMS-P 2.10.5 정보전송 보안 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다."

### F-2.10.5-02 · ExternalName Service 평문 호출 발견
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.5-02",
  "name": "ExternalName Service 평문 호출 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Service",
    "required_data": ["cluster_services"],
    "condition": { "operator": "all_of", "conditions": [{ "field": "spec.type", "equals": "ExternalName" }, { "field": "spec.externalName", "regex_match": "^http://" }] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.5", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "외부 송수신 시 평문 전송", "match": "direct" }],
    "additional_review_items": ["평문 호출이 비중요 외부 서비스인가", "중요 정보 송수신이면 https:// 변경 필요"],
    "manual_check_areas": ["외부 호출 인터페이스 목록"],
    "automation_coverage": { "percentage": 100, "covered": "ExternalName http:// 점검", "not_covered": "실제 호출되는 도메인의 정책" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- ExternalName 서비스가 `http://`(평문) 엔드포인트를 가리키는지 찾아낸 뒤, 중요정보 경로 여부는 사람이 검토.
- **집계 대상 테이블** — `cluster_services`
- **사람 검토 영역** — 외부 호출 인터페이스 목록
- **자동화 커버리지** — 100% (ExternalName http:// 점검), 실제 호출 도메인 정책은 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 평문 호출 대상이 개인정보/중요정보를 송수신하지 않는 비중요 외부 서비스로 확인됨(중요정보면 https 전환 필요)
- **인증기준의 어느 부분을 보는가** — 2.10.5 인증기준의 **전송 시 암호화**(평문 외부 호출 탐지)를 본다.
- ISMS-P 2.10.5 정보전송 보안 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다."

### R-2.10.5-01 · 외부 공개 Ingress TLS 미설정
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.5-01",
  "name": "외부 공개 Ingress TLS 미설정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "ingress.spec.tls", "op": "!=", "value": null, "description": "외부 공개 Ingress에 .spec.tls 설정 존재 — HTTPS 전송 암호화 적용" },
    { "field": "tls_covers_all_hosts", "op": "==", "value": true, "description": "Ingress의 모든 host가 TLS secretName에 의해 커버됨" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 외부 Ingress에 TLS가 설정되고 모든 host가 커버되는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_ingresses` / 컬럼: `ingress_class`, `rules`(JSONB), `tls`(JSONB)
- **JSON 필드 ↔ DB 매핑** — `ingress.spec.tls` = `cluster_ingresses.tls`; `tls_covers_all_hosts`는 **파생값**(`rules`의 host 목록이 모두 `tls`의 host에 포함되는지).
- 판정 기준: tls 설정 존재 AND 모든 host 커버 ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.5 인증기준의 **전송 중 기술적 보호(전 host TLS)**를 본다.
- ISMS-P 2.10.5 정보전송 보안 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다."

### R-2.10.5-03 · ExternalName Service 평문 endpoint
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.5-03",
  "name": "ExternalName Service 평문 endpoint",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "tls_verification": { "annotation": "isms-p/tls-verified", "hostname_pattern_check": "endpoint가 https:// 프로토콜이 아닌 경우 평문으로 판단", "dns_tls_port_hints": [443, 8443] },
  "compliance_indicators": [
    { "field": "externalname_endpoint_is_tls", "op": "==", "value": true, "description": "ExternalName Service의 외부 endpoint가 TLS 사용 (HTTPS endpoint 또는 tls-verified annotation 존재)" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- ExternalName 서비스의 외부 endpoint가 TLS를 쓰는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_services` / 컬럼: `name`, `type`, `external_name`, `selector`·`ports`(JSONB)
- **JSON 필드 ↔ DB 매핑** — `externalname_endpoint_is_tls`는 **파생값**. 계산 과정: `external_name`이 `https://`/TLS 포트(443·8443)이거나 `isms-p/tls-verified` annotation이 있으면 `True`, `http://`면 `False`.
- 판정 기준: `externalname_endpoint_is_tls == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.5 인증기준의 **외부 전송 암호화**(평문 endpoint 배제)를 본다.
- ISMS-P 2.10.5 정보전송 보안 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다."

### R-2.10.5-GL01 · 안전한 정보전송 정책 수립
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.5-GL01",
  "name": "안전한 정보전송 정책 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["업무 목적으로 개인정보 및 중요정보를 전송할 때 안전한 전송 정책을 수립하고 전송 중 보호를 위한 기술적 대책을 적용한다."],
  "compliance_indicators": [{ "description": "개인정보·중요정보 전송 시 안전한 전송 정책과 기술적 보호대책을 적용하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.5", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「업무 목적으로 개인정보 및 중요정보를 전송할 때 안전한 전송 정책을 수립하고 전송 중 보호를 위한 기술적 대책을 적용한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.5 인증기준 "…**안전한 전송 정책을 수립하고…기술적 대책을 적용**…" 구절.
- ISMS-P 2.10.5 정보전송 보안 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다."

### R-2.10.5-GL02 · 조직 간 교환 협약 체결
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.5-GL02",
  "name": "조직 간 교환 협약 체결",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["업무상 조직 간에 개인정보 및 중요정보를 상호교환하는 경우 안전한 전송을 위한 협약 체결 등 보호대책을 수립·이행한다."],
  "compliance_indicators": [{ "description": "조직 간 정보 교환 시 협약 체결 등 보호대책을 수립·이행하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.5", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「업무상 조직 간에 개인정보 및 중요정보를 상호교환하는 경우 안전한 전송을 위한 협약 체결 등 보호대책을 수립·이행한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.5 인증기준의 **안전한 전송 정책** 중 조직 간 교환 협약 측면을 본다.
- ISMS-P 2.10.5 정보전송 보안 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다."

## 2.10.8 패치관리

### F-2.10.8-01 · Node Kubernetes 버전 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.8-01",
  "name": "Node Kubernetes 버전 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Node",
    "required_data": ["cluster_nodes"],
    "condition": { "operator": "kubelet_version_check", "min_supported": "current_stable - 2" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.8", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "EOL 시스템 운영", "match": "direct" }],
    "additional_review_items": ["EKS 지원 버전 정책과 비교", "패치 일정 계획 확인"],
    "manual_check_areas": [],
    "automation_coverage": { "percentage": 100, "covered": "K8s 자체 버전", "not_covered": "제어 플레인(EKS 관리형), 노드 OS 버전" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 노드 kubelet 버전이 지원 범위(최신 stable-2) 내인지 집계한 뒤, EKS 지원 정책·패치 일정은 사람이 검토.
- **집계 대상 테이블** — `cluster_nodes`
- **사람 검토 영역** — EKS 지원 버전 정책 비교, 패치 일정 계획
- **자동화 커버리지** — 100% (K8s 버전), 제어 플레인·노드 OS 버전은 제외
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - kubeletVersion이 EKS 지원 버전 범위 내이거나, 패치 일정 계획상 지원 버전 업그레이드가 결재·관리되고 있음(EOL 운영이면 결함)
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **EOL/패치 미적용 방지**(지원 버전 운영)를 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### F-2.10.8-02 · 이미지 태그 안정성 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.8-02",
  "name": "이미지 태그 안정성 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": ["cluster_pods.containers[].image"],
    "condition": { "operator": "tag_mutable_check", "mutable_patterns": ["latest", "stable", "prod", "main", "master"] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.8", "match_strength": "indirect" }],
    "additional_review_items": ["mutable 태그 정책이 회사 표준에 부합하는가", "패치 적용 시점 추적이 다른 방식으로 가능한가"],
    "manual_check_areas": ["이미지 태그 정책", "CI/CD 빌드 추적 시스템"],
    "automation_coverage": { "percentage": 100, "covered": "이미지 태그 안정성", "not_covered": "실제 패치 적용 추적" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 컨테이너 이미지가 mutable 태그(latest 등)를 쓰는지 집계한 뒤, 회사 태그 정책·빌드 추적은 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.containers[].image`
- **사람 검토 영역** — 이미지 태그 정책, CI/CD 빌드 추적 시스템
- **자동화 커버리지** — 100% (태그 안정성), 실제 패치 적용 추적은 수동
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - mutable 태그여도 CI/CD 빌드 추적 시스템으로 실제 배포 이미지·패치 시점이 추적 가능함
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **패치 추적성**(mutable 태그로 인한 추적 불가 위험)을 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### F-2.10.8-03 · 이미지 디지스트 고정 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.8-03",
  "name": "이미지 디지스트 고정 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": ["cluster_pods.containers[].image_digest"],
    "condition": { "operator": "digest_present" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.8", "match_strength": "indirect" }],
    "additional_review_items": ["digest 미고정이 회사 표준에 부합하는가", "이미지 무결성을 다른 방식으로 보장하는가"],
    "manual_check_areas": ["이미지 무결성 정책", "이미지 서명/검증 운영"],
    "automation_coverage": { "percentage": 100, "covered": "디지스트 고정 여부", "not_covered": "외부 스캐너 기반 취약점 점검" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 컨테이너 이미지가 digest로 고정됐는지 집계한 뒤, 무결성 정책·서명 운영은 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.containers[].image_digest`
- **사람 검토 영역** — 이미지 무결성 정책, 이미지 서명/검증 운영
- **자동화 커버리지** — 100% (digest 고정 여부), 외부 스캐너 취약점 점검은 제외
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - digest 미고정이어도 이미지 서명/검증(Cosign/Notation 등)으로 이미지 무결성이 보장됨
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **패치 무결성**(고정 digest로 동일 빌드 보장)을 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### F-2.10.8-04 · 실행 중 이미지 알려진 취약점(CVE) 현황
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.10.8-04",
  "name": "실행 중 이미지 알려진 취약점(CVE) 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": ["cluster_pods.containers[].image_digest", "image_vulnerabilities"],
    "condition": { "operator": "cve_vulnerability_check", "min_severity": "HIGH" },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.10.8", "match_strength": "direct" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "알려진 취약점 패치 미적용", "match": "direct" }],
    "additional_review_items": ["Trivy/Clair 등 이미지 스캔 도구 운영 여부", "Critical CVE 긴급 패치 프로세스", "취약점 관리 정책/기록"],
    "manual_check_areas": ["취약점 관리 정책", "이미지 스캔 운영 현황"],
    "automation_coverage": { "percentage": 80, "covered": "Trivy 기반 CVE 스캔", "not_covered": "OS 패치, 커스텀 취약점" },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

- 실행 중 이미지의 HIGH 이상 CVE를 스캔한 뒤, 취약점 관리 정책·긴급 패치 프로세스는 사람이 검토.
- **집계 대상 테이블** — `cluster_pods.containers[].image_digest`, `image_vulnerabilities`
- **사람 검토 영역** — 취약점 관리 정책, 이미지 스캔 운영 현황
- **자동화 커버리지** — 80% (Trivy 기반 CVE 스캔), OS 패치·커스텀 취약점은 제외
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 발견된 CVE가 취약점 관리 정책상 예외 승인/완화조치로 처리됐거나, 긴급 패치 프로세스로 조치(예정)됨
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **알려진 취약점 패치 적용**(미패치 CVE 잔존 여부)을 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-01 · Node kubeletVersion EOL
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-01",
  "name": "Node kubeletVersion EOL",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "eol_policy": { "description": "EKS는 Kubernetes minor version을 약 14개월간 지원. EOL 이후 보안 패치 미제공", "check_method": "kubeletVersion의 minor version과 현재 지원되는 EKS 버전 목록 대조" },
  "compliance_indicators": [
    { "field": "node_kubelet_version_supported", "op": "==", "value": true, "description": "Node kubeletVersion이 AWS EKS 지원 버전 범위 내 — 보안 패치 제공 대상" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 노드 kubelet 버전이 EKS 지원(비-EOL) 범위인지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_nodes` / 컬럼: `kubelet_version`, `os_image`, `container_runtime`
- **JSON 필드 ↔ DB 매핑** — `node_kubelet_version_supported`는 **파생값**. 계산 과정: `kubelet_version`의 minor 버전을 현재 EKS 지원 버전 목록(약 14개월)과 대조해 범위 내면 `True`.
- 판정 기준: `node_kubelet_version_supported == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **EOL 방지(패치 제공 대상 유지)**를 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-02 · 이미지 태그 mutable
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-02",
  "name": "이미지 태그 mutable",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "mutable_tag_patterns": ["latest", "stable", "dev", "staging", "main", "master"],
  "compliance_indicators": [
    { "field": "all_images_use_immutable_tag", "op": "==", "value": true, "description": "모든 컨테이너 이미지가 버전 고정 태그 또는 digest 사용 — 패치 추적 가능" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 모든 컨테이너 이미지가 버전 고정 태그/digest를 쓰는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `containers` (JSONB: 이미지 태그·digest·포트)
- **JSON 필드 ↔ DB 매핑** — `all_images_use_immutable_tag`는 **파생값**. 계산 과정: ① `containers`의 각 `image` 태그/digest 파싱 → ② 태그가 `mutable_tag_patterns`(latest·stable·dev·staging·main·master)와 매칭되거나 태그·digest가 없으면 그 컨테이너는 mutable → ③ 전부 mutable 아니면 `True`.
- 판정 기준: `all_images_use_immutable_tag == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **패치 추적 가능성**(고정 태그)을 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-03 · 이미지 digest 미고정
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-03",
  "name": "이미지 digest 미고정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    { "field": "all_images_pinned_by_digest", "op": "==", "value": true, "description": "모든 컨테이너 이미지가 @sha256: digest로 고정됨 — 동일 빌드 보장, 패치 무결성 확인 가능" }
  ],
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 모든 컨테이너 이미지가 `@sha256:` digest로 고정됐는지 자동 판정한다.
- **가져오는 곳** — 테이블: `cluster_pods` / 컬럼: `containers` (JSONB: 이미지 태그·digest·포트)
- **JSON 필드 ↔ DB 매핑** — `all_images_pinned_by_digest`는 **파생값**. 계산 과정: `containers`의 각 `image` 문자열에 `@sha256:` digest가 포함됐는지 확인 → 전부 포함이면 `True`.
- 판정 기준: `all_images_pinned_by_digest == True` ⇒ 준수
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 **패치 무결성**(동일 빌드 보장)을 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-GL01 · 패치 적용 절차 및 정기 적용
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-GL01",
  "name": "패치 적용 절차 및 정기 적용",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용 절차를 수립하고 정기적으로 패치를 적용한다."],
  "compliance_indicators": [{ "description": "보안 패치 적용 절차를 수립하고 정기적으로 패치를 적용하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.8", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용 절차를 수립하고 정기적으로 패치를 적용한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준 "…**절차를 수립하고, 정기적으로 패치를 적용**…" 구절.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-GL02 · 패치 적용 곤란 시 보완대책
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-GL02",
  "name": "패치 적용 곤란 시 보완대책",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["서비스 영향도 등으로 최신 패치 적용이 어려운 경우 보완대책을 마련한다."],
  "compliance_indicators": [{ "description": "최신 패치 적용이 어려운 경우 보완대책을 마련하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.8", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「서비스 영향도 등으로 최신 패치 적용이 어려운 경우 보완대책을 마련한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 예외 처리, 즉 **패치 곤란 시 보완대책** 규정 여부를 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-GL03 · 주요 시스템 패치 경로 제한
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-GL03",
  "name": "주요 시스템 패치 경로 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["주요 서버·네트워크시스템·보안시스템 등은 공개 인터넷 접속을 통한 패치를 제한한다."],
  "compliance_indicators": [{ "description": "주요 시스템의 공개 인터넷을 통한 패치를 제한하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.8", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「주요 서버·네트워크시스템·보안시스템 등은 공개 인터넷 접속을 통한 패치를 제한한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 패치 안전성, 즉 **주요 시스템 패치 경로 제한** 규정 여부를 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

### R-2.10.8-GL04 · 패치관리시스템 보호
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.10.8-GL04",
  "name": "패치관리시스템 보호",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["패치관리시스템(PMS)을 활용하는 경우 접근통제 등 충분한 보호대책을 마련한다."],
  "compliance_indicators": [{ "description": "패치관리시스템 활용 시 접근통제 등 보호대책을 마련하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.10.8", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「패치관리시스템(PMS)을 활용하는 경우 접근통제 등 충분한 보호대책을 마련한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.10.8 인증기준의 패치 인프라 보호, 즉 **PMS 접근통제** 규정 여부를 본다.
- ISMS-P 2.10.8 패치관리 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다."

## 2.11.3 이상행위 분석 및 모니터링

### F-2.11.3-01 · 운영 환경 Shell 활동 관찰 (eBPF)
🧑‍💻 클라우드 수동 점검(F-룰)

- 실제 룰 JSON

```json
{
  "rule_id": "F-2.11.3-01",
  "name": "운영 환경 Shell 활동 관찰 (eBPF)",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "eBPF process events",
    "required_data": ["ebpf_process_events", "cluster_namespaces"],
    "condition": { "operator": "prod_shell_exec_detection", "time_window": "24h", "binary_patterns": ["/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/bin/zsh"] },
    "compliance_mappings": [{ "framework": "ISMS-P", "item": "2.11.3", "match_strength": "indirect" }],
    "kisa_defect_case_refs": [{ "case_number": null, "description": "모니터링 사각지대 - 운영 중 비정상 활동 미감지", "match": "partial" }],
    "additional_review_items": ["발견된 shell exec이 인가된 운영 작업이었는가", "kubectl exec 권한 보유 SA 식별", "활동 시간대가 업무 시간 내인가", "회사의 운영 접근 정책 확인"],
    "manual_check_areas": ["이상행위 탐지 도구 운영(Falco, Tetragon)", "탐지 룰 정의 문서", "모니터링 로그 보관 정책"],
    "automation_coverage": { "percentage": 30, "covered": "eBPF 기반 shell 활동", "not_covered": "audit log 기반 비정상 활동(burst 요청, Forbidden 응답 등)" },
    "alternative_controls": ["SSM Session Manager", "Teleport", "외부 PAM 도구"],
    "k8s_only_check": true,
    "deferred": false,
    "deferred_reason": "K8s audit log 미수집으로 burst/forbidden/unexpected_creator 룰 비활성"
  }
}
```

- eBPF로 운영 namespace 내 shell 실행을 24시간 관찰한 뒤, 인가 작업 여부·탐지 도구 운영은 사람이 검토.
- **집계 대상 테이블** — `ebpf_process_events`, `cluster_namespaces`
- **사람 검토 영역** — 이상행위 탐지 도구 운영(Falco, Tetragon), 탐지 룰 정의 문서, 모니터링 로그 보관 정책
- **자동화 커버리지** — 30% (eBPF shell 활동), audit log 기반 비정상 활동은 제외(audit log 미수집)
- **K8s 외 충족 조건** — K8s 점검에서 미충족·미확인이어도 다음 중 하나가 성립하면 충족(모두 아니면 결함):
  - 탐지된 shell exec이 인가된 운영 작업(결재·SSM Session Manager/Teleport/PAM 기록)으로 확인됨
  - 이상행위 탐지 도구(Falco/Tetragon)와 모니터링 로그 보관 정책이 운영되고 있음
- **인증기준의 어느 부분을 보는가** — 2.11.3 인증기준의 **이상행위 탐지 모니터링**(운영 환경 비정상 shell 접근 감지)을 본다.
- ISMS-P 2.11.3 이상행위 분석 및 모니터링 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다."

### R-2.11.3-01 · prod 환경 shell exec 활동
⚙️ 클라우드 실측(K8s API)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.11.3-01",
  "name": "prod 환경 shell exec 활동",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "prod_namespace_indicators": { "labels": ["env=production", "env=prod", "environment=production"], "name_patterns": ["prod-*", "*-prod", "*-production"] },
  "exec_detection": { "audit_log_verb": "create", "audit_log_resource": "pods/exec", "description": "Kubernetes Audit Log에서 pods/exec create 이벤트를 탐지하여 운영 환경 shell 접근 모니터링" },
  "compliance_indicators": [
    { "field": "prod_exec_detected", "op": "==", "value": false, "description": "운영 환경 namespace에서 Pod exec 활동 미탐지 — 비인가 shell 접근 없음" }
  ],
  "alert_on_detection": { "severity": "high", "description": "운영 환경 Pod exec는 긴급 장애 대응 외 허용되지 않음 — 즉시 조사 필요" },
  "judgment_logic": { "type": "structured_match", "aggregation": "all_compliance_required", "min_pass_ratio": 1.0 }
}
```

- 운영 namespace에서 Pod exec(shell 접근) 활동이 탐지되는지 자동 판정한다.
- **가져오는 곳** — 테이블: `ebpf_process_events` (런타임 프로세스 exec 이벤트, eBPF 에이전트 수집). (원문 설계는 K8s Audit Log의 `pods/exec` create지만, audit log 미수집으로 eBPF 이벤트로 대체)
- **JSON 필드 ↔ DB 매핑** — `prod_exec_detected`는 **파생값**. 계산 과정: `cluster_namespaces`에서 운영 namespace(env=prod 라벨/이름 패턴)를 식별 → 해당 ns에서 `ebpf_process_events`에 shell exec 이벤트가 있으면 `True`.
- 판정 기준: `prod_exec_detected == False` ⇒ 준수(비인가 shell 접근 없음)
- **인증기준의 어느 부분을 보는가** — 2.11.3 인증기준의 **이상행위 탐지**(운영 환경 비인가 exec 감지)를 본다.
- ISMS-P 2.11.3 이상행위 분석 및 모니터링 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다."

### R-2.11.3-GL01 · 이상행위 모니터링 체계 구축
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.11.3-GL01",
  "name": "이상행위 모니터링 체계 구축",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["네트워크 및 시스템의 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축한다."],
  "compliance_indicators": [{ "description": "이상행위 탐지·분석을 위한 모니터링 체계를 구축하도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.11.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「네트워크 및 시스템의 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.11.3 인증기준 "…**모니터링 체계를 구축**…" 구절.
- ISMS-P 2.11.3 이상행위 분석 및 모니터링 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다."

### R-2.11.3-GL02 · 이상행위 기준·임계치 및 적시 대응
📄 지침·정책 점검(RAG)

- 실제 룰 JSON

```json
{
  "rule_id": "R-2.11.3-GL02",
  "name": "이상행위 기준·임계치 및 적시 대응",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": ["침해시도, 개인정보 유출시도, 부정행위 등을 판단하기 위한 기준 및 임계치를 정의하고, 이에 따라 이상행위의 판단·조사 등 후속 조치가 적시에 이루어지도록 한다."],
  "compliance_indicators": [{ "description": "이상행위 판단 기준·임계치를 정의하고 적시 후속 조치가 이루어지도록 규정" }],
  "source_reference": { "framework": "ISMS-P", "item": "2.11.3", "basis": "안내서 주요 확인사항/인증기준" },
  "judgment_logic": { "type": "semantic_match", "method": "llm_rag_entailment", "match_criteria": "sentence_semantic_equivalence", "verdict_states": ["충족", "미충족", "확인불가"] }
}
```

- **점검 기준 문장(keywords)**: 「침해시도, 개인정보 유출시도, 부정행위 등을 판단하기 위한 기준 및 임계치를 정의하고, 이에 따라 이상행위의 판단·조사 등 후속 조치가 적시에 이루어지도록 한다.」 / 판정: 충족·미충족·확인불가
- **인증기준의 어느 부분을 보는가** — 2.11.3 인증기준 "…**이상행위 발생 시 적시에 대응**…절차를 수립·이행…" 중 판단 기준·임계치·적시 대응 측면.
- ISMS-
