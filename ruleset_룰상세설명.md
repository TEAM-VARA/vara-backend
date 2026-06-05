# ISMS-P 룰셋 상세 설명서 (전체 147룰)

각 룰: ① 실제 JSON ② 쉽게 설명 ③ 무엇을/어디를 확인(DB 테이블·컬럼 / 지침 문장 / 증적 키) ④ 당위성

> ⚠️ k8s 룰은 클러스터 스냅샷이 적재된 `cluster_*` 테이블에서 값을 읽는다(assembler가 DB row→평가요청으로 조립). namespace 라벨은 `cluster_namespaces`에 컬럼이 없어 현재 미적재 상태임에 유의.

---

# 1.2.1 정보자산 식별

## F-1.2.1-01 · K8s 클러스터 자산 인벤토리
*🧑‍💻 클라우드 수동 점검(F-룰)*
> 🔧 변경: 중복 점검항목 제거(분류문서 보유/실사기록 → GL01·GL03·GL04로 일원화)

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-1.2.1-01",
  "name": "K8s 클러스터 자산 인벤토리",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Cluster",
    "required_data": [
      "cluster_namespaces",
      "cluster_pods",
      "cluster_services",
      "cluster_configmaps"
    ],
    "condition": {
      "operator": "inventory_report"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "1.2.1",
        "match_strength": "supportive"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": 4,
        "description": "외부 위탁 IT 서비스 자산 식별 누락",
        "match": "partial"
      }
    ],
    "additional_review_items": [
      "이 K8s 자산 목록이 회사 자산관리대장에 포함되어 있는가",
      "K8s 외 자산(온프레미스, 외부 위탁 등)은 별도 식별되어 있는가"
    ],
    "manual_check_areas": [
      "외부 위탁 자산 식별 절차",
      "자산관리시스템(CMDB)"
    ],
    "automation_coverage": {
      "percentage": 30,
      "covered": "K8s 클러스터 내 자산 식별",
      "not_covered": "외부 자산, 분류 기준 합리성, 중요도 평가"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_namespaces`, `cluster_pods`, `cluster_services`, `cluster_configmaps`
  - 사람 검토 영역: 외부 위탁 자산 식별 절차, 자산관리시스템(CMDB)

**④ 당위성**
ISMS-P **1.2.1 정보자산 식별** 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.1-01 · namespace 자산 분류 라벨
*⚙️ 클라우드 실측(K8s, DB 적재값)*
> 🔧 변경: verdict_type=needs_review 강등 (※엔진 미반영 — pod_graph_evaluator 패치 필요)

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.1-01",
  "name": "namespace 자산 분류 라벨",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "namespace.metadata.labels.data-classification",
      "op": "in",
      "value": [
        "public",
        "internal",
        "confidential",
        "pii",
        "sensitive-pii"
      ],
      "description": "데이터 분류 등급 라벨 존재"
    },
    {
      "field": "namespace.metadata.labels.isms-p/owner",
      "op": "!=",
      "value": null,
      "description": "자산 책임자 라벨 존재"
    },
    {
      "field": "namespace.metadata.labels.isms-p/criticality",
      "op": "in",
      "value": [
        "critical",
        "high",
        "medium",
        "low"
      ],
      "description": "자산 중요도 라벨 존재"
    }
  ],
  "activates_on_pass": [
    {
      "condition": "data-classification == pii",
      "require": [
        "R-2.7.1-POD-01",
        "R-2.9.4-POD"
      ],
      "note": "PII 등급 시 etcd 암호화 + 1년 이상 접속기록 필수"
    },
    {
      "condition": "data-classification == sensitive-pii",
      "require": [
        "R-2.9.4-POD"
      ],
      "note": "민감 PII 시 2년 이상 접속기록 필수"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  },
  "verdict_type": "needs_review"
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'namespace 자산 분류 라벨' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_namespaces.namespace` (TEXT). ⚠️ 라벨 컬럼이 없어 namespace 라벨은 DB에 적재되지 않음 — assembler가 빈 값으로 채움(현 구조상 라벨 기반 판정 불가)
  - 판정 기준: `namespace.metadata.labels.data-classification in ['public', 'internal', 'confidential', 'pii', 'sensitive-pii']`; `namespace.metadata.labels.isms-p/criticality in ['critical', 'high', 'medium', 'low']`

**④ 당위성**
ISMS-P **1.2.1 정보자산 식별** 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.1-GL01 · 정보자산 분류기준 수립
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.1-GL01",
  "name": "정보자산 분류기준 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "관리체계 범위 내 모든 정보자산을 식별·분류하기 위한 분류기준을 수립한다."
  ],
  "compliance_indicators": [
    {
      "description": "조직의 업무특성에 따라 정보자산 분류기준을 수립하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "1.2.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'정보자산 분류기준 수립'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「관리체계 범위 내 모든 정보자산을 식별·분류하기 위한 분류기준을 수립한다.」

**④ 당위성**
ISMS-P **1.2.1 정보자산 식별** 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.1-GL02 · 중요도 산정 및 보안등급 부여
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.1-GL02",
  "name": "중요도 산정 및 보안등급 부여",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "식별된 정보자산에 대하여 법적 요구사항 및 업무 영향도를 고려하여 중요도를 산정하고 보안등급을 부여한다."
  ],
  "compliance_indicators": [
    {
      "description": "정보자산의 중요도를 결정하고 보안등급을 부여하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "1.2.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'중요도 산정 및 보안등급 부여'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「식별된 정보자산에 대하여 법적 요구사항 및 업무 영향도를 고려하여 중요도를 산정하고 보안등급을 부여한다.」

**④ 당위성**
ISMS-P **1.2.1 정보자산 식별** 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.1-GL03 · 정보자산 목록 최신 유지
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.1-GL03",
  "name": "정보자산 목록 최신 유지",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정기적으로 정보자산 현황을 조사하여 정보자산 목록을 최신 상태로 유지한다."
  ],
  "compliance_indicators": [
    {
      "description": "정기적으로 정보자산 현황을 조사하여 목록을 최신으로 유지하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "1.2.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'정보자산 목록 최신 유지'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정기적으로 정보자산 현황을 조사하여 정보자산 목록을 최신 상태로 유지한다.」

**④ 당위성**
ISMS-P **1.2.1 정보자산 식별** 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.1-GL04 · 분류기준 정책의 버전·승인·갱신 관리
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-1.2.1-02(정책 버전·승인·갱신) 문장 GL로 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.1-GL04",
  "name": "분류기준 정책의 버전·승인·갱신 관리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정보자산 분류기준 정책에는 버전·승인자·승인일자를 명시하고 최소 1년에 한 번 이상 갱신하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "분류기준 정책에 버전·승인자·승인일자가 명시되고 정기적으로(연 1회 이상) 갱신하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "1.2.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'분류기준 정책의 버전·승인·갱신 관리'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정보자산 분류기준 정책에는 버전·승인자·승인일자를 명시하고 최소 1년에 한 번 이상 갱신하도록 규정한다.」

**④ 당위성**
ISMS-P **1.2.1 정보자산 식별** 인증기준: "조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

# 1.2.2 현황 및 흐름분석

## F-1.2.2-01 · 클러스터 내부 통신 관계 인벤토리
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-1.2.2-01",
  "name": "클러스터 내부 통신 관계 인벤토리",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Cluster",
    "required_data": [
      "cluster_services",
      "cluster_ingresses",
      "cluster_network_policies",
      "cluster_pods"
    ],
    "condition": {
      "operator": "traffic_graph_report"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "1.2.2",
        "match_strength": "supportive"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "이 통신 관계가 회사 정보흐름도에 반영되어 있는가",
      "개인정보 처리 흐름이 별도 표시되어 있는가"
    ],
    "manual_check_areas": [
      "개인정보 처리 시스템 흐름도"
    ],
    "automation_coverage": {
      "percentage": 30,
      "covered": "K8s 통신 관계",
      "not_covered": "흐름도 문서 자체, K8s 외 시스템 연계"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_services`, `cluster_ingresses`, `cluster_network_policies`, `cluster_pods`
  - 사람 검토 영역: 개인정보 처리 시스템 흐름도

**④ 당위성**
ISMS-P **1.2.2 현황 및 흐름분석** 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## F-1.2.2-02 · 외부 의존성 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-1.2.2-02",
  "name": "외부 의존성 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Service + eBPF",
    "required_data": [
      "cluster_services",
      "ebpf_dns_queries"
    ],
    "condition": {
      "operator": "external_dependency_report",
      "filter": {
        "type": "ExternalName"
      }
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "1.2.2",
        "match_strength": "supportive"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "발견된 외부 의존성이 모두 정보흐름도에 등록되어 있는가",
      "미등록 외부 연계 사유 확인",
      "외부 위탁 계약 현황 매칭"
    ],
    "manual_check_areas": [
      "외부 위탁 계약서",
      "외부 연계 시스템 목록"
    ],
    "automation_coverage": {
      "percentage": 50,
      "covered": "클러스터에서 보이는 외부 연결",
      "not_covered": "K8s 외 시스템의 외부 연결"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_services`, `ebpf_dns_queries`
  - 사람 검토 영역: 외부 위탁 계약서, 외부 연계 시스템 목록

**④ 당위성**
ISMS-P **1.2.2 현황 및 흐름분석** 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.2-01 · 외부 의존성 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.2-01",
  "name": "외부 의존성 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "externalname_service.metadata.labels.isms-p/external-dependency",
      "op": "!=",
      "value": null,
      "description": "ExternalName Service에 외부 의존성 분류 라벨 존재"
    },
    {
      "field": "externalname_service.metadata.labels.isms-p/data-flow-id",
      "op": "!=",
      "value": null,
      "description": "흐름도 매핑 ID 라벨 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '외부 의존성 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_services` (name, type, cluster_ip, external_name, selector·ports JSONB, external_ips JSONB)

**④ 당위성**
ISMS-P **1.2.2 현황 및 흐름분석** 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.2-02 · Ingress 흐름도 등록 annotation 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.2-02",
  "name": "Ingress 흐름도 등록 annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "ingress.metadata.annotations.isms-p/flow-diagram-registered",
      "op": "==",
      "value": "true",
      "description": "Ingress에 흐름도 등록 annotation 존재"
    },
    {
      "field": "ingress.metadata.annotations.isms-p/service-flow-id",
      "op": "!=",
      "value": null,
      "description": "정보서비스 흐름도 ID annotation 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'Ingress 흐름도 등록 annotation 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `ingress.metadata.annotations.isms-p/flow-diagram-registered == true`

**④ 당위성**
ISMS-P **1.2.2 현황 및 흐름분석** 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.2-GL01 · 정보서비스·개인정보 흐름도 작성
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.2-GL01",
  "name": "정보서비스·개인정보 흐름도 작성",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고 정보서비스 흐름도·개인정보 흐름도 등으로 문서화한다."
  ],
  "compliance_indicators": [
    {
      "description": "업무절차와 흐름을 파악하여 정보서비스 흐름도·개인정보 흐름도로 문서화하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "1.2.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'정보서비스·개인정보 흐름도 작성'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고 정보서비스 흐름도·개인정보 흐름도 등으로 문서화한다.」

**④ 당위성**
ISMS-P **1.2.2 현황 및 흐름분석** 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-1.2.2-GL02 · 흐름도 최신성 유지
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-1.2.2-GL02",
  "name": "흐름도 최신성 유지",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "서비스·업무·정보자산의 변화에 따라 업무절차 및 개인정보 흐름을 주기적으로 검토하여 흐름도 등 관련 문서의 최신성을 유지한다."
  ],
  "compliance_indicators": [
    {
      "description": "변화에 따라 흐름도 등 관련 문서를 주기적으로 검토·갱신하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "1.2.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'흐름도 최신성 유지'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「서비스·업무·정보자산의 변화에 따라 업무절차 및 개인정보 흐름을 주기적으로 검토하여 흐름도 등 관련 문서의 최신성을 유지한다.」

**④ 당위성**
ISMS-P **1.2.2 현황 및 흐름분석** 인증기준: "관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

# 2.1.3 정보자산 관리

## F-2.1.3-01 · Pod 책임자 정보 부재
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.1.3-01",
  "name": "Pod 책임자 정보 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "additional_evidence",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": [
      "cluster_pods.annotations",
      "cluster_pods.labels"
    ],
    "condition": {
      "operator": "any_owner_indicator_exists",
      "fields": [
        "annotations.owner",
        "annotations.contact",
        "labels.team"
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.1.3",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "회사가 K8s annotation으로 책임자를 관리하는 정책인가",
      "외부 자산관리시스템(CMDB)에서 책임자 매핑 여부",
      "책임자 미지정 자산의 사유 확인"
    ],
    "manual_check_areas": [
      "자산관리시스템(CMDB) 책임자 매핑"
    ],
    "automation_coverage": {
      "percentage": 30,
      "covered": "K8s 라벨 기반 책임자 식별",
      "not_covered": "외부 시스템 매핑, 책임 위임 절차"
    },
    "alternative_controls": [
      "외부 CMDB",
      "ITSM 시스템"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.annotations`, `cluster_pods.labels`
  - 사람 검토 영역: 자산관리시스템(CMDB) 책임자 매핑

**④ 당위성**
ISMS-P **2.1.3 정보자산 관리** 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## F-2.1.3-02 · 자산 변경 활동 감지
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.1.3-02",
  "name": "자산 변경 활동 감지",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "Workload (history)",
    "required_data": [
      "cluster_workloads (snapshot history)"
    ],
    "condition": {
      "operator": "change_activity_report",
      "time_window": "7d"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.1.3",
        "match_strength": "supportive"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "이 변경 사항이 회사 자산관리 절차를 거쳤는가",
      "자산관리대장에 반영되었는가",
      "변경 신청/승인 결재 기록과 매칭"
    ],
    "manual_check_areas": [
      "변경관리 시스템(ITSM)",
      "자산관리대장"
    ],
    "automation_coverage": {
      "percentage": 100,
      "covered": "변경 감지",
      "not_covered": "변경 절차 준수 여부"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_workloads (snapshot history)`
  - 사람 검토 영역: 변경관리 시스템(ITSM), 자산관리대장

**④ 당위성**
ISMS-P **2.1.3 정보자산 관리** 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.1.3-01 · 워크로드 owner annotation 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.1.3-01",
  "name": "워크로드 owner annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "workload.metadata.annotations.isms-p/owner",
      "op": "!=",
      "value": null,
      "description": "워크로드에 자산 책임자(owner) annotation 존재"
    },
    {
      "field": "workload.metadata.annotations.isms-p/owner-team",
      "op": "!=",
      "value": null,
      "description": "워크로드에 소유 팀(owner-team) annotation 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '워크로드 owner annotation 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.annotations` (JSONB) — 해당 어노테이션 키 조회

**④ 당위성**
ISMS-P **2.1.3 정보자산 관리** 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.1.3-02 · security-class 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.1.3-02",
  "name": "security-class 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "workload.metadata.labels.security-class",
      "op": "in",
      "value": [
        "critical",
        "high",
        "medium",
        "low"
      ],
      "description": "워크로드에 유효한 보안등급(security-class) 라벨 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'security-class 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.labels` (JSONB) — 해당 키 조회 (예: `labels ->> 'data-classification'`)
  - 판정 기준: `workload.metadata.labels.security-class in ['critical', 'high', 'medium', 'low']`

**④ 당위성**
ISMS-P **2.1.3 정보자산 관리** 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.1.3-GL01 · 보안등급별 취급절차·보호대책 정의
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.1.3-GL01",
  "name": "보안등급별 취급절차·보호대책 정의",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정보자산의 보안등급에 따른 취급절차 및 보호대책을 정의하고 이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "보안등급에 따른 취급절차와 보호대책을 정의·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.1.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'보안등급별 취급절차·보호대책 정의'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정보자산의 보안등급에 따른 취급절차 및 보호대책을 정의하고 이행한다.」

**④ 당위성**
ISMS-P **2.1.3 정보자산 관리** 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.1.3-GL02 · 자산 책임자·관리자 지정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.1.3-GL02",
  "name": "자산 책임자·관리자 지정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "식별된 정보자산에 대하여 책임자 및 관리자를 지정한다."
  ],
  "compliance_indicators": [
    {
      "description": "식별된 정보자산에 책임자 및 관리자를 지정하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.1.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'자산 책임자·관리자 지정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「식별된 정보자산에 대하여 책임자 및 관리자를 지정한다.」

**④ 당위성**
ISMS-P **2.1.3 정보자산 관리** 인증기준: "식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

# 2.10.2 클라우드 보안

## R-2.10.2-08 · Namespace Pod Security Admission 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.2-08",
  "name": "Namespace Pod Security Admission 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "psa_levels": [
    "privileged",
    "baseline",
    "restricted"
  ],
  "compliance_indicators": [
    {
      "field": "namespace.metadata.labels.pod-security.kubernetes.io/enforce",
      "op": "in",
      "value": [
        "baseline",
        "restricted"
      ],
      "description": "PSA enforce 라벨이 baseline 또는 restricted로 설정됨"
    },
    {
      "field": "namespace.metadata.labels.pod-security.kubernetes.io/audit",
      "op": "in",
      "value": [
        "baseline",
        "restricted"
      ],
      "description": "PSA audit 라벨이 baseline 또는 restricted로 설정됨"
    }
  ],
  "exception_check": {
    "annotation": "psa-exception/justification",
    "system_namespaces": [
      "kube-system",
      "kube-node-lease",
      "kube-public"
    ]
  },
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'Namespace Pod Security Admission 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_namespaces.namespace` (TEXT). ⚠️ 라벨 컬럼이 없어 namespace 라벨은 DB에 적재되지 않음 — assembler가 빈 값으로 채움(현 구조상 라벨 기반 판정 불가)
  - 판정 기준: `namespace.metadata.labels.pod-security.kubernetes.io/enforce in ['baseline', 'restricted']`; `namespace.metadata.labels.pod-security.kubernetes.io/audit in ['baseline', 'restricted']`

**④ 당위성**
ISMS-P **2.10.2 클라우드 보안** 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.2-GL01 · 클라우드 유형별 위험평가·대책
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.2-GL01",
  "name": "클라우드 유형별 위험평가·대책",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "클라우드 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고 이에 맞는 보안대책을 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "클라우드 서비스 유형별 보안 위험을 평가하고 보안대책을 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'클라우드 유형별 위험평가·대책'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「클라우드 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고 이에 맞는 보안대책을 수립·이행한다.」

**④ 당위성**
ISMS-P **2.10.2 클라우드 보안** 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.2-GL02 · 클라우드 관리자 권한 최소화·보호
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.2-GL02",
  "name": "클라우드 관리자 권한 최소화·보호",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "클라우드 서비스 관리자 권한을 역할에 따라 최소화하여 부여하고, 강화된 인증·암호화·접근통제·감사기록 등 보호대책을 적용한다."
  ],
  "compliance_indicators": [
    {
      "description": "클라우드 관리자 권한 최소 부여 및 강화 인증·감사기록 등 보호대책 적용을 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'클라우드 관리자 권한 최소화·보호'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「클라우드 서비스 관리자 권한을 역할에 따라 최소화하여 부여하고, 강화된 인증·암호화·접근통제·감사기록 등 보호대책을 적용한다.」

**④ 당위성**
ISMS-P **2.10.2 클라우드 보안** 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.2-GL03 · 클라우드 설정·운영 모니터링
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.2-GL03",
  "name": "클라우드 설정·운영 모니터링",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "클라우드 서비스의 보안 설정 변경·운영 현황 등을 모니터링하고 그 적절성을 정기적으로 검토한다."
  ],
  "compliance_indicators": [
    {
      "description": "클라우드 보안 설정·운영 현황을 모니터링하고 정기 검토하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'클라우드 설정·운영 모니터링'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「클라우드 서비스의 보안 설정 변경·운영 현황 등을 모니터링하고 그 적절성을 정기적으로 검토한다.」

**④ 당위성**
ISMS-P **2.10.2 클라우드 보안** 인증기준: "클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

# 2.10.3 공개서버 보안

## F-2.10.3-03 · NodePort 노출 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.3-03",
  "name": "NodePort 노출 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Service",
    "required_data": [
      "cluster_services"
    ],
    "condition": {
      "operator": "field_equals",
      "field": "spec.type",
      "value": "NodePort"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.3",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "발견된 NodePort가 의도된 공개인가",
      "VPC SG에서 노드의 NodePort 차단되어 있는가"
    ],
    "manual_check_areas": [
      "NodePort 사용 정책",
      "VPC Security Group 설정"
    ],
    "automation_coverage": {
      "percentage": 50,
      "covered": "NodePort Service 식별",
      "not_covered": "VPC SG 차단 여부"
    },
    "alternative_controls": [
      "VPC Security Group",
      "Network ACL"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_services`
  - 사람 검토 영역: NodePort 사용 정책, VPC Security Group 설정

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-01 · LoadBalancer source range 미설정
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-01",
  "name": "LoadBalancer source range 미설정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "service.spec.loadBalancerSourceRanges",
      "op": "!=",
      "value": null,
      "description": "loadBalancerSourceRanges 설정됨 — 접근 허용 IP 대역 제한"
    },
    {
      "field": "source_range_not_all_open",
      "op": "==",
      "value": true,
      "description": "0.0.0.0/0 전체 허용이 아닌 특정 IP 대역으로 제한됨"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'LoadBalancer source range 미설정' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_services` (name, type, cluster_ip, external_name, selector·ports JSONB, external_ips JSONB)
  - 판정 기준: `source_range_not_all_open == True`

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-02 · 공개 Ingress WAF annotation 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-02",
  "name": "공개 Ingress WAF annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "waf_annotations": [
    "alb.ingress.kubernetes.io/wafv2-acl-arn",
    "alb.ingress.kubernetes.io/waf-acl-id",
    "nginx.ingress.kubernetes.io/modsecurity-snippet"
  ],
  "compliance_indicators": [
    {
      "field": "public_ingress_has_waf",
      "op": "==",
      "value": true,
      "description": "공개 Ingress에 WAF(AWS WAFv2 ACL 또는 ModSecurity) annotation 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '공개 Ingress WAF annotation 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `public_ingress_has_waf == True`

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-03 · NodePort Service 공개 의도 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-03",
  "name": "NodePort Service 공개 의도 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "nodeport_service.metadata.labels.exposure-intent",
      "op": "in",
      "value": [
        "public",
        "internal-only",
        "debug"
      ],
      "description": "NodePort Service에 공개 의도 라벨(exposure-intent) 존재 — 의도적 노출임을 명시"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'NodePort Service 공개 의도 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_services` (name, type, cluster_ip, external_name, selector·ports JSONB, external_ips JSONB)
  - 판정 기준: `nodeport_service.metadata.labels.exposure-intent in ['public', 'internal-only', 'debug']`

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-04 · 공개 Ingress rate limit 미설정
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-04",
  "name": "공개 Ingress rate limit 미설정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "rate_limit_annotations": [
    "nginx.ingress.kubernetes.io/limit-rps",
    "nginx.ingress.kubernetes.io/limit-rpm",
    "nginx.ingress.kubernetes.io/limit-connections",
    "alb.ingress.kubernetes.io/actions.rate-limit"
  ],
  "compliance_indicators": [
    {
      "field": "public_ingress_has_rate_limit",
      "op": "==",
      "value": true,
      "description": "공개 Ingress에 rate limit annotation 설정됨 — DDoS/과다요청 방어"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '공개 Ingress rate limit 미설정' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `public_ingress_has_rate_limit == True`

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-05 · LoadBalancer 공개 의도 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-05",
  "name": "LoadBalancer 공개 의도 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "lb_service.metadata.labels.exposure-intent",
      "op": "in",
      "value": [
        "public",
        "internal-only"
      ],
      "description": "LoadBalancer Service에 공개 의도 라벨(exposure-intent) 존재 — 외부 노출 의도 명시"
    },
    {
      "field": "lb_has_internal_annotation_or_public_label",
      "op": "==",
      "value": true,
      "description": "internal LB annotation 또는 public exposure-intent 라벨 중 하나 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'LoadBalancer 공개 의도 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_services` (name, type, cluster_ip, external_name, selector·ports JSONB, external_ips JSONB)
  - 판정 기준: `lb_service.metadata.labels.exposure-intent in ['public', 'internal-only']`; `lb_has_internal_annotation_or_public_label == True`

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-GL01 · 공개서버 분리·강화 보호대책
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-GL01",
  "name": "공개서버 분리·강화 보호대책",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "외부에 공개되는 서버는 내부 네트워크와 분리하고, 취약점 점검·접근통제·이상징후 모니터링 등 강화된 보호대책을 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "공개서버를 내부망과 분리하고 강화된 보호대책을 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'공개서버 분리·강화 보호대책'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「외부에 공개되는 서버는 내부 네트워크와 분리하고, 취약점 점검·접근통제·이상징후 모니터링 등 강화된 보호대책을 수립·이행한다.」

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-GL02 · 공개서버 게시 허가 절차
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-GL02",
  "name": "공개서버 게시 허가 절차",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "공개서버에 개인정보 및 중요정보를 게시·저장해야 하는 경우 책임자 승인 등 허가 및 게시 절차를 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "공개서버 게시·저장 시 책임자 승인 등 허가·게시 절차를 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'공개서버 게시 허가 절차'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「공개서버에 개인정보 및 중요정보를 게시·저장해야 하는 경우 책임자 승인 등 허가 및 게시 절차를 수립·이행한다.」

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.3-GL03 · 중요정보 노출 점검·차단
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.3-GL03",
  "name": "중요정보 노출 점검·차단",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "조직의 중요정보가 웹사이트·웹서버를 통해 노출되는지 주기적으로 확인하고, 노출을 인지한 경우 즉시 차단 등의 조치를 취한다."
  ],
  "compliance_indicators": [
    {
      "description": "웹을 통한 중요정보 노출을 주기적으로 점검하고 인지 시 즉시 차단하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'중요정보 노출 점검·차단'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「조직의 중요정보가 웹사이트·웹서버를 통해 노출되는지 주기적으로 확인하고, 노출을 인지한 경우 즉시 차단 등의 조치를 취한다.」

**④ 당위성**
ISMS-P **2.10.3 공개서버 보안** 인증기준: "외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

# 2.10.5 정보전송 보안

## F-2.10.5-01 · 외부 공개 Ingress TLS 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.5-01",
  "name": "외부 공개 Ingress TLS 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Ingress",
    "required_data": [
      "cluster_ingresses"
    ],
    "condition": {
      "operator": "field_non_empty",
      "field": "spec.tls",
      "scope": "external_only"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.5",
        "match_strength": "direct"
      },
      {
        "framework": "개인정보보호법",
        "item": "안전성 확보조치 - 전송 시 암호화",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "HTTP 통신으로 개인정보 송수신",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "미설정 Ingress가 개인정보/중요정보 송수신 경로인가",
      "외부 LB에서 TLS 종료 + 클러스터 내 mTLS 구조인가"
    ],
    "manual_check_areas": [
      "송수신 인터페이스 목록",
      "개인정보 처리 시스템 흐름도"
    ],
    "automation_coverage": {
      "percentage": 40,
      "covered": "K8s Ingress TLS",
      "not_covered": "mTLS, 외부 LB TLS"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_ingresses`
  - 사람 검토 영역: 송수신 인터페이스 목록, 개인정보 처리 시스템 흐름도

**④ 당위성**
ISMS-P **2.10.5 정보전송 보안** 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## F-2.10.5-02 · ExternalName Service 평문 호출 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.5-02",
  "name": "ExternalName Service 평문 호출 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Service",
    "required_data": [
      "cluster_services"
    ],
    "condition": {
      "operator": "all_of",
      "conditions": [
        {
          "field": "spec.type",
          "equals": "ExternalName"
        },
        {
          "field": "spec.externalName",
          "regex_match": "^http://"
        }
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.5",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "외부 송수신 시 평문 전송",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "평문 호출이 비중요 외부 서비스인가",
      "중요 정보 송수신이면 https:// 변경 필요"
    ],
    "manual_check_areas": [
      "외부 호출 인터페이스 목록"
    ],
    "automation_coverage": {
      "percentage": 100,
      "covered": "ExternalName http:// 점검",
      "not_covered": "실제 호출되는 도메인의 정책"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_services`
  - 사람 검토 영역: 외부 호출 인터페이스 목록

**④ 당위성**
ISMS-P **2.10.5 정보전송 보안** 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.5-01 · 외부 공개 Ingress TLS 미설정
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.5-01",
  "name": "외부 공개 Ingress TLS 미설정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "ingress.spec.tls",
      "op": "!=",
      "value": null,
      "description": "외부 공개 Ingress에 .spec.tls 설정 존재 — HTTPS 전송 암호화 적용"
    },
    {
      "field": "tls_covers_all_hosts",
      "op": "==",
      "value": true,
      "description": "Ingress의 모든 host가 TLS secretName에 의해 커버됨"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '외부 공개 Ingress TLS 미설정' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `tls_covers_all_hosts == True`

**④ 당위성**
ISMS-P **2.10.5 정보전송 보안** 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.5-03 · ExternalName Service 평문 endpoint
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.5-03",
  "name": "ExternalName Service 평문 endpoint",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "tls_verification": {
    "annotation": "isms-p/tls-verified",
    "hostname_pattern_check": "endpoint가 https:// 프로토콜이 아닌 경우 평문으로 판단",
    "dns_tls_port_hints": [
      443,
      8443
    ]
  },
  "compliance_indicators": [
    {
      "field": "externalname_endpoint_is_tls",
      "op": "==",
      "value": true,
      "description": "ExternalName Service의 외부 endpoint가 TLS 사용 (HTTPS endpoint 또는 tls-verified annotation 존재)"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'ExternalName Service 평문 endpoint' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_services` (name, type, cluster_ip, external_name, selector·ports JSONB, external_ips JSONB)
  - 판정 기준: `externalname_endpoint_is_tls == True`

**④ 당위성**
ISMS-P **2.10.5 정보전송 보안** 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.5-GL01 · 안전한 정보전송 정책 수립
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.5-GL01",
  "name": "안전한 정보전송 정책 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "업무 목적으로 개인정보 및 중요정보를 전송할 때 안전한 전송 정책을 수립하고 전송 중 보호를 위한 기술적 대책을 적용한다."
  ],
  "compliance_indicators": [
    {
      "description": "개인정보·중요정보 전송 시 안전한 전송 정책과 기술적 보호대책을 적용하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.5",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'안전한 정보전송 정책 수립'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「업무 목적으로 개인정보 및 중요정보를 전송할 때 안전한 전송 정책을 수립하고 전송 중 보호를 위한 기술적 대책을 적용한다.」

**④ 당위성**
ISMS-P **2.10.5 정보전송 보안** 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.5-GL02 · 조직 간 교환 협약 체결
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.5-GL02",
  "name": "조직 간 교환 협약 체결",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "업무상 조직 간에 개인정보 및 중요정보를 상호교환하는 경우 안전한 전송을 위한 협약 체결 등 보호대책을 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "조직 간 정보 교환 시 협약 체결 등 보호대책을 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.5",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'조직 간 교환 협약 체결'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「업무상 조직 간에 개인정보 및 중요정보를 상호교환하는 경우 안전한 전송을 위한 협약 체결 등 보호대책을 수립·이행한다.」

**④ 당위성**
ISMS-P **2.10.5 정보전송 보안** 인증기준: "업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

# 2.10.8 패치관리

## F-2.10.8-01 · Node Kubernetes 버전 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.8-01",
  "name": "Node Kubernetes 버전 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Node",
    "required_data": [
      "cluster_nodes"
    ],
    "condition": {
      "operator": "kubelet_version_check",
      "min_supported": "current_stable - 2"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "EOL 시스템 운영",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "EKS 지원 버전 정책과 비교",
      "패치 일정 계획 확인"
    ],
    "manual_check_areas": [],
    "automation_coverage": {
      "percentage": 100,
      "covered": "K8s 자체 버전",
      "not_covered": "제어 플레인(EKS 관리형), 노드 OS 버전"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_nodes`

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## F-2.10.8-02 · 이미지 태그 안정성 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.8-02",
  "name": "이미지 태그 안정성 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": [
      "cluster_pods.containers[].image"
    ],
    "condition": {
      "operator": "tag_mutable_check",
      "mutable_patterns": [
        "latest",
        "stable",
        "prod",
        "main",
        "master"
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "mutable 태그 정책이 회사 표준에 부합하는가",
      "패치 적용 시점 추적이 다른 방식으로 가능한가"
    ],
    "manual_check_areas": [
      "이미지 태그 정책",
      "CI/CD 빌드 추적 시스템"
    ],
    "automation_coverage": {
      "percentage": 100,
      "covered": "이미지 태그 안정성",
      "not_covered": "실제 패치 적용 추적"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.containers[].image`
  - 사람 검토 영역: 이미지 태그 정책, CI/CD 빌드 추적 시스템

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## F-2.10.8-03 · 이미지 디지스트 고정 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.8-03",
  "name": "이미지 디지스트 고정 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": [
      "cluster_pods.containers[].image_digest"
    ],
    "condition": {
      "operator": "digest_present"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "digest 미고정이 회사 표준에 부합하는가",
      "이미지 무결성을 다른 방식으로 보장하는가"
    ],
    "manual_check_areas": [
      "이미지 무결성 정책",
      "이미지 서명/검증 운영"
    ],
    "automation_coverage": {
      "percentage": 100,
      "covered": "디지스트 고정 여부",
      "not_covered": "외부 스캐너 기반 취약점 점검"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.containers[].image_digest`
  - 사람 검토 영역: 이미지 무결성 정책, 이미지 서명/검증 운영

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## F-2.10.8-04 · 실행 중 이미지 알려진 취약점(CVE) 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.10.8-04",
  "name": "실행 중 이미지 알려진 취약점(CVE) 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": [
      "cluster_pods.containers[].image_digest",
      "image_vulnerabilities"
    ],
    "condition": {
      "operator": "cve_vulnerability_check",
      "min_severity": "HIGH"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "알려진 취약점 패치 미적용",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "Trivy/Clair 등 이미지 스캔 도구 운영 여부",
      "Critical CVE 긴급 패치 프로세스",
      "취약점 관리 정책/기록"
    ],
    "manual_check_areas": [
      "취약점 관리 정책",
      "이미지 스캔 운영 현황"
    ],
    "automation_coverage": {
      "percentage": 80,
      "covered": "Trivy 기반 CVE 스캔",
      "not_covered": "OS 패치, 커스텀 취약점"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.containers[].image_digest`, `image_vulnerabilities`
  - 사람 검토 영역: 취약점 관리 정책, 이미지 스캔 운영 현황

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-01 · Node kubeletVersion EOL
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-01",
  "name": "Node kubeletVersion EOL",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "eol_policy": {
    "description": "EKS는 Kubernetes minor version을 약 14개월간 지원. EOL 이후 보안 패치 미제공",
    "check_method": "kubeletVersion의 minor version과 현재 지원되는 EKS 버전 목록 대조"
  },
  "compliance_indicators": [
    {
      "field": "node_kubelet_version_supported",
      "op": "==",
      "value": true,
      "description": "Node kubeletVersion이 AWS EKS 지원 버전 범위 내 — 보안 패치 제공 대상"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'Node kubeletVersion EOL' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_nodes` (kubelet_version, os_image, container_runtime)
  - 판정 기준: `node_kubelet_version_supported == True`

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-02 · 이미지 태그 mutable
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-02",
  "name": "이미지 태그 mutable",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "mutable_tag_patterns": [
    "latest",
    "stable",
    "dev",
    "staging",
    "main",
    "master"
  ],
  "compliance_indicators": [
    {
      "field": "all_images_use_immutable_tag",
      "op": "==",
      "value": true,
      "description": "모든 컨테이너 이미지가 버전 고정 태그 또는 digest 사용 — 패치 추적 가능"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '이미지 태그 mutable' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.containers` (JSONB: 이미지 태그/digest·포트)
  - 판정 기준: `all_images_use_immutable_tag == True`

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-03 · 이미지 digest 미고정
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-03",
  "name": "이미지 digest 미고정",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "all_images_pinned_by_digest",
      "op": "==",
      "value": true,
      "description": "모든 컨테이너 이미지가 @sha256: digest로 고정됨 — 동일 빌드 보장, 패치 무결성 확인 가능"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '이미지 digest 미고정' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.containers` (JSONB: 이미지 태그/digest·포트)
  - 판정 기준: `all_images_pinned_by_digest == True`

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-GL01 · 패치 적용 절차 및 정기 적용
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-GL01",
  "name": "패치 적용 절차 및 정기 적용",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용 절차를 수립하고 정기적으로 패치를 적용한다."
  ],
  "compliance_indicators": [
    {
      "description": "보안 패치 적용 절차를 수립하고 정기적으로 패치를 적용하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.8",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'패치 적용 절차 및 정기 적용'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용 절차를 수립하고 정기적으로 패치를 적용한다.」

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-GL02 · 패치 적용 곤란 시 보완대책
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-GL02",
  "name": "패치 적용 곤란 시 보완대책",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "서비스 영향도 등으로 최신 패치 적용이 어려운 경우 보완대책을 마련한다."
  ],
  "compliance_indicators": [
    {
      "description": "최신 패치 적용이 어려운 경우 보완대책을 마련하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.8",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'패치 적용 곤란 시 보완대책'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「서비스 영향도 등으로 최신 패치 적용이 어려운 경우 보완대책을 마련한다.」

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-GL03 · 주요 시스템 패치 경로 제한
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-GL03",
  "name": "주요 시스템 패치 경로 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "주요 서버·네트워크시스템·보안시스템 등은 공개 인터넷 접속을 통한 패치를 제한한다."
  ],
  "compliance_indicators": [
    {
      "description": "주요 시스템의 공개 인터넷을 통한 패치를 제한하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.8",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'주요 시스템 패치 경로 제한'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「주요 서버·네트워크시스템·보안시스템 등은 공개 인터넷 접속을 통한 패치를 제한한다.」

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.10.8-GL04 · 패치관리시스템 보호
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.10.8-GL04",
  "name": "패치관리시스템 보호",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "패치관리시스템(PMS)을 활용하는 경우 접근통제 등 충분한 보호대책을 마련한다."
  ],
  "compliance_indicators": [
    {
      "description": "패치관리시스템 활용 시 접근통제 등 보호대책을 마련하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.10.8",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'패치관리시스템 보호'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「패치관리시스템(PMS)을 활용하는 경우 접근통제 등 충분한 보호대책을 마련한다.」

**④ 당위성**
ISMS-P **2.10.8 패치관리** 인증기준: "소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

# 2.11.3 이상행위 분석 및 모니터링

## F-2.11.3-01 · 운영 환경 Shell 활동 관찰 (eBPF)
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.11.3-01",
  "name": "운영 환경 Shell 활동 관찰 (eBPF)",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "eBPF process events",
    "required_data": [
      "ebpf_process_events",
      "cluster_namespaces"
    ],
    "condition": {
      "operator": "prod_shell_exec_detection",
      "time_window": "24h",
      "binary_patterns": [
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/sh",
        "/usr/bin/bash",
        "/bin/zsh"
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.11.3",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "모니터링 사각지대 - 운영 중 비정상 활동 미감지",
        "match": "partial"
      }
    ],
    "additional_review_items": [
      "발견된 shell exec이 인가된 운영 작업이었는가",
      "kubectl exec 권한 보유 SA 식별",
      "활동 시간대가 업무 시간 내인가",
      "회사의 운영 접근 정책 확인"
    ],
    "manual_check_areas": [
      "이상행위 탐지 도구 운영(Falco, Tetragon)",
      "탐지 룰 정의 문서",
      "모니터링 로그 보관 정책"
    ],
    "automation_coverage": {
      "percentage": 30,
      "covered": "eBPF 기반 shell 활동",
      "not_covered": "audit log 기반 비정상 활동(burst 요청, Forbidden 응답 등)"
    },
    "alternative_controls": [
      "SSM Session Manager",
      "Teleport",
      "외부 PAM 도구"
    ],
    "k8s_only_check": true,
    "deferred": false,
    "deferred_reason": "K8s audit log 미수집으로 burst/forbidden/unexpected_creator 룰 비활성"
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `ebpf_process_events`, `cluster_namespaces`
  - 사람 검토 영역: 이상행위 탐지 도구 운영(Falco, Tetragon), 탐지 룰 정의 문서, 모니터링 로그 보관 정책

**④ 당위성**
ISMS-P **2.11.3 이상행위 분석 및 모니터링** 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.11.3-01 · prod 환경 shell exec 활동
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.11.3-01",
  "name": "prod 환경 shell exec 활동",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "prod_namespace_indicators": {
    "labels": [
      "env=production",
      "env=prod",
      "environment=production"
    ],
    "name_patterns": [
      "prod-*",
      "*-prod",
      "*-production"
    ]
  },
  "exec_detection": {
    "audit_log_verb": "create",
    "audit_log_resource": "pods/exec",
    "description": "Kubernetes Audit Log에서 pods/exec create 이벤트를 탐지하여 운영 환경 shell 접근 모니터링"
  },
  "compliance_indicators": [
    {
      "field": "prod_exec_detected",
      "op": "==",
      "value": false,
      "description": "운영 환경 namespace에서 Pod exec 활동 미탐지 — 비인가 shell 접근 없음"
    }
  ],
  "alert_on_detection": {
    "severity": "high",
    "description": "운영 환경 Pod exec는 긴급 장애 대응 외 허용되지 않음 — 즉시 조사 필요"
  },
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'prod 환경 shell exec 활동' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `ebpf_process_events` (런타임 프로세스 exec 이벤트 — eBPF 에이전트 수집)
  - 판정 기준: `prod_exec_detected == False`

**④ 당위성**
ISMS-P **2.11.3 이상행위 분석 및 모니터링** 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.11.3-GL01 · 이상행위 모니터링 체계 구축
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.11.3-GL01",
  "name": "이상행위 모니터링 체계 구축",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "네트워크 및 시스템의 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축한다."
  ],
  "compliance_indicators": [
    {
      "description": "이상행위 탐지·분석을 위한 모니터링 체계를 구축하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.11.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'이상행위 모니터링 체계 구축'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「네트워크 및 시스템의 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축한다.」

**④ 당위성**
ISMS-P **2.11.3 이상행위 분석 및 모니터링** 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.11.3-GL02 · 이상행위 기준·임계치 및 적시 대응
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.11.3-GL02",
  "name": "이상행위 기준·임계치 및 적시 대응",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "침해시도, 개인정보 유출시도, 부정행위 등을 판단하기 위한 기준 및 임계치를 정의하고, 이에 따라 이상행위의 판단·조사 등 후속 조치가 적시에 이루어지도록 한다."
  ],
  "compliance_indicators": [
    {
      "description": "이상행위 판단 기준·임계치를 정의하고 적시 후속 조치가 이루어지도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.11.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'이상행위 기준·임계치 및 적시 대응'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「침해시도, 개인정보 유출시도, 부정행위 등을 판단하기 위한 기준 및 임계치를 정의하고, 이에 따라 이상행위의 판단·조사 등 후속 조치가 적시에 이루어지도록 한다.」

**④ 당위성**
ISMS-P **2.11.3 이상행위 분석 및 모니터링** 인증기준: "네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

# 2.5.1 사용자 계정 관리

## F-2.5.1-01 · default ServiceAccount 사용 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.5.1-01",
  "name": "default ServiceAccount 사용 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": [
      "cluster_pods.service_account",
      "cluster_pods.namespace"
    ],
    "condition": {
      "operator": "in_set",
      "field": "service_account",
      "values": [
        "",
        "default"
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.1",
        "match_strength": "direct"
      },
      {
        "framework": "개인정보보호법",
        "item": "안전성 확보조치 - 계정 분리",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "공용 계정 사용",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "해당 Pod가 인증범위 내 자산인가",
      "default SA 사용에 대한 회사 정책상 예외 허용 사례인가",
      "시스템 namespace는 예외 처리"
    ],
    "manual_check_areas": [
      "공용 계정 사용 예외 승인 기록"
    ],
    "automation_coverage": {
      "percentage": 100,
      "covered": "K8s 내 공용계정 패턴",
      "not_covered": "사람 사용자 계정(외부 IdP)"
    },
    "exception_conditions": {
      "exception_namespaces": [
        "kube-system",
        "kube-public",
        "kube-node-lease"
      ]
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.service_account`, `cluster_pods.namespace`
  - 사람 검토 영역: 공용 계정 사용 예외 승인 기록

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## F-2.5.1-02 · 미사용(orphan) ServiceAccount 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.5.1-02",
  "name": "미사용(orphan) ServiceAccount 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount",
    "required_data": [
      "cluster_service_accounts",
      "cluster_role_bindings",
      "cluster_cluster_role_bindings"
    ],
    "condition": {
      "operator": "orphan_serviceaccount"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.1",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "불필요 계정 정기 점검/삭제 미흡",
        "match": "partial"
      }
    ],
    "additional_review_items": [
      "이 SA들이 계획된 향후 사용을 위한 것인가",
      "정기 점검 미실시로 잔존한 계정인가",
      "회사의 계정 정기 점검 주기/기록 확인"
    ],
    "manual_check_areas": [
      "최근 점검 기록"
    ],
    "automation_coverage": {
      "percentage": 80,
      "covered": "K8s SA 정리 상태",
      "not_covered": "점검 절차 운영 여부"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_service_accounts`, `cluster_role_bindings`, `cluster_cluster_role_bindings`
  - 사람 검토 영역: 최근 점검 기록

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.1-01 · default ServiceAccount 사용
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.1-01",
  "name": "default ServiceAccount 사용",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "pod.spec.serviceAccountName",
      "op": "!=",
      "value": "default",
      "description": "Pod가 전용 ServiceAccount를 사용 (default SA 미사용)"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'default ServiceAccount 사용' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.service_account` (TEXT)
  - 판정 기준: `pod.spec.serviceAccountName != default`

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.1-02 · ServiceAccount owner 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.1-02",
  "name": "ServiceAccount owner 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "serviceaccount.metadata.labels.isms-p/owner",
      "op": "!=",
      "value": null,
      "description": "ServiceAccount에 소유자(owner) 라벨 존재"
    },
    {
      "field": "serviceaccount.metadata.labels.isms-p/purpose",
      "op": "!=",
      "value": null,
      "description": "ServiceAccount에 용도(purpose) 라벨 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'ServiceAccount owner 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.service_account` (TEXT)
  - `cluster_service_accounts` (name, namespace, secrets JSONB)

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.1-03 · 팀 간 ServiceAccount 공유
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.1-03",
  "name": "팀 간 ServiceAccount 공유",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "sa_shared_across_teams",
      "op": "==",
      "value": false,
      "description": "동일 ServiceAccount를 서로 다른 팀의 워크로드가 공유하지 않음"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '팀 간 ServiceAccount 공유' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.service_account` (TEXT)
  - `cluster_workloads` (kind, selector, template_labels JSONB, containers JSONB)
  - 판정 기준: `sa_shared_across_teams == False`

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.1-GL01 · 계정·권한 생애주기 절차 수립
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.1-GL01",
  "name": "계정·권한 생애주기 절차 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정보시스템 및 개인정보처리시스템의 사용자 등록·해지 및 접근권한 부여·변경·말소에 관한 공식적인 절차를 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "사용자 등록·해지 및 접근권한 부여·변경·말소 공식 절차를 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.5.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'계정·권한 생애주기 절차 수립'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정보시스템 및 개인정보처리시스템의 사용자 등록·해지 및 접근권한 부여·변경·말소에 관한 공식적인 절차를 수립·이행한다.」

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.1-GL02 · 직무별 최소권한 부여
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.1-GL02",
  "name": "직무별 최소권한 부여",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "사용자 등록·변경 시 직무별 접근권한 분류체계에 따라 업무상 필요한 최소한의 권한만 부여한다."
  ],
  "compliance_indicators": [
    {
      "description": "직무별 접근권한 분류체계에 따라 최소권한만 부여하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.5.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'직무별 최소권한 부여'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「사용자 등록·변경 시 직무별 접근권한 분류체계에 따라 업무상 필요한 최소한의 권한만 부여한다.」

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.1-GL03 · 계정 보안책임 인식
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.1-GL03",
  "name": "계정 보안책임 인식",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "사용자에게 계정 및 접근권한을 부여할 때 해당 계정의 보안책임이 본인에게 있음을 명확히 인식시킨다."
  ],
  "compliance_indicators": [
    {
      "description": "계정 보안책임이 본인에게 있음을 인식시키도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.5.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'계정 보안책임 인식'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「사용자에게 계정 및 접근권한을 부여할 때 해당 계정의 보안책임이 본인에게 있음을 명확히 인식시킨다.」

**④ 당위성**
ISMS-P **2.5.1 사용자 계정 관리** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

# 2.5.2 사용자 식별

## F-2.5.2-01 · 추측 가능한 명칭의 ServiceAccount 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.5.2-01",
  "name": "추측 가능한 명칭의 ServiceAccount 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount",
    "required_data": [
      "cluster_service_accounts.name"
    ],
    "condition": {
      "operator": "regex_match",
      "field": "name",
      "pattern": "^(admin|root|test|temp|guest)(-.*)?$"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.2",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "admin, guest, test 등 추측 가능한 ID 운영",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "해당 SA가 인증범위 내 자산인가",
      "명명 자체보다 권한 범위 점검(F-2.5.5와 결합)",
      "회사 명명 규칙 문서와 비교"
    ],
    "manual_check_areas": [],
    "automation_coverage": {
      "percentage": 80,
      "covered": "K8s SA 명명 점검",
      "not_covered": "사람 사용자 ID 체계"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_service_accounts.name`

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## F-2.5.2-02 · 일반 명명 패턴 ServiceAccount 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.5.2-02",
  "name": "일반 명명 패턴 ServiceAccount 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount",
    "required_data": [
      "cluster_service_accounts.name"
    ],
    "condition": {
      "operator": "regex_match",
      "field": "name",
      "pattern": "^(user|account|sa)[0-9]+$"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.2",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "용도가 의미적으로 식별 가능한가",
      "운영 표준 명명 규칙과 일치하는가"
    ],
    "manual_check_areas": [],
    "automation_coverage": {
      "percentage": 80,
      "covered": "명명 규칙 점검만",
      "not_covered": "실제 사용 패턴"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_service_accounts.name`

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.2-01 · 추측 가능한 SA 이름
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.2-01",
  "name": "추측 가능한 SA 이름",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "guessable_name_patterns": [
    "^admin$",
    "^root$",
    "^test$",
    "^user$",
    "^sa$",
    "^service$",
    "^app$",
    "^demo$",
    "^temp$",
    "^tmp$"
  ],
  "compliance_indicators": [
    {
      "field": "sa_name_is_guessable",
      "op": "==",
      "value": false,
      "description": "ServiceAccount 이름이 추측 불가능한 고유 식별명 사용"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '추측 가능한 SA 이름' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.service_account` (TEXT)
  - 판정 기준: `sa_name_is_guessable == False`

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.2-02 · 일반 명명 패턴
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.2-02",
  "name": "일반 명명 패턴",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "generic_naming_patterns": [
    "^sa-[0-9]+$",
    "^serviceaccount-[0-9]+$",
    "^svc-account-[0-9]+$",
    "^user[0-9]+$",
    "^account[0-9]+$"
  ],
  "compliance_indicators": [
    {
      "field": "sa_name_is_generic",
      "op": "==",
      "value": false,
      "description": "ServiceAccount 이름이 워크로드·기능을 식별할 수 있는 명명규칙 준수"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '일반 명명 패턴' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.service_account` (TEXT)
  - 판정 기준: `sa_name_is_generic == False`

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.2-GL01 · 사용자별 유일 식별자 부여
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.2-GL01",
  "name": "사용자별 유일 식별자 부여",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정보시스템 및 개인정보·중요정보에 대한 접근을 사용자별로 고유하게 식별할 수 있도록 유일한 식별자를 부여한다."
  ],
  "compliance_indicators": [
    {
      "description": "사용자별로 고유하게 식별 가능한 유일 식별자를 부여하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.5.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'사용자별 유일 식별자 부여'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정보시스템 및 개인정보·중요정보에 대한 접근을 사용자별로 고유하게 식별할 수 있도록 유일한 식별자를 부여한다.」

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.2-GL02 · 추측 가능한 식별자 사용 제한
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.2-GL02",
  "name": "추측 가능한 식별자 사용 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "추측하기 쉬운 식별자(root, admin, test 등)의 사용을 제한한다."
  ],
  "compliance_indicators": [
    {
      "description": "추측하기 쉬운 식별자 사용을 제한하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.5.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'추측 가능한 식별자 사용 제한'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「추측하기 쉬운 식별자(root, admin, test 등)의 사용을 제한한다.」

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.2-GL03 · 공유 식별자 통제
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.2-GL03",
  "name": "공유 식별자 통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "불가피하게 동일한 식별자를 공유하는 경우 그 사유와 타당성을 검토하고 보완대책을 마련하여 책임자의 승인을 받는다."
  ],
  "compliance_indicators": [
    {
      "description": "식별자 공유 시 사유·타당성 검토와 보완대책, 책임자 승인을 받도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.5.2",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'공유 식별자 통제'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「불가피하게 동일한 식별자를 공유하는 경우 그 사유와 타당성을 검토하고 보완대책을 마련하여 책임자의 승인을 받는다.」

**④ 당위성**
ISMS-P **2.5.2 사용자 식별** 인증기준: "정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

# 2.5.4 비밀번호 관리

## R-2.5.4-03 · OS 패스워드 정책 설정값 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-03",
  "name": "OS 패스워드 정책 설정값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "/etc/login.defs",
    "/etc/pam.d/",
    "pam_pwquality",
    "PASS_MAX_DAYS",
    "PASS_MIN_LEN",
    "minlen",
    "dcredit",
    "ucredit",
    "ocredit",
    "lcredit"
  ],
  "compliance_indicators": [
    {
      "field": "PASS_MAX_DAYS",
      "op": "<=",
      "value": 180,
      "description": "최대 유효기간 180일 이하"
    },
    {
      "field": "PASS_MIN_LEN",
      "op": ">=",
      "value": 8,
      "description": "최소 길이 8자 이상"
    },
    {
      "field": "minlen",
      "op": ">=",
      "value": 10,
      "description": "pam_pwquality 최소 10자"
    },
    {
      "field": "dcredit",
      "op": "<=",
      "value": -1,
      "description": "숫자 강제 포함"
    },
    {
      "field": "ucredit",
      "op": "<=",
      "value": -1,
      "description": "대문자 강제 포함"
    },
    {
      "field": "ocredit",
      "op": "<=",
      "value": -1,
      "description": "특수문자 강제 포함"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'OS 패스워드 정책 설정값 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `PASS_MAX_DAYS`, `PASS_MIN_LEN`, `minlen`, `dcredit`, `ucredit`, `ocredit`
  - 판정 기준: `PASS_MAX_DAYS <= 180`; `PASS_MIN_LEN >= 8`; `minlen >= 10`; `dcredit <= -1`; `ucredit <= -1`; `ocredit <= -1`

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-04 · AD 패스워드 정책 설정값 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-04",
  "name": "AD 패스워드 정책 설정값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "Group Policy",
    "Default Domain Policy",
    "Account Policies",
    "Password Policy",
    "Password must meet complexity requirements",
    "gpedit.msc",
    "secpol.msc"
  ],
  "compliance_indicators": [
    {
      "field": "Minimum password length",
      "op": ">=",
      "value": 8
    },
    {
      "field": "Maximum password age",
      "op": "<=",
      "value": 180,
      "unit": "days"
    },
    {
      "field": "Password must meet complexity requirements",
      "op": "==",
      "value": "Enabled"
    },
    {
      "field": "Enforce password history",
      "op": ">=",
      "value": 4
    },
    {
      "field": "Account lockout threshold",
      "op": "<=",
      "value": 5,
      "op_exclude": [
        0
      ]
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'AD 패스워드 정책 설정값 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `Minimum password length`, `Maximum password age`, `Password must meet complexity requirements`, `Enforce password history`, `Account lockout threshold`
  - 판정 기준: `Minimum password length >= 8`; `Maximum password age <= 180days`; `Password must meet complexity requirements == Enabled`; `Enforce password history >= 4`; `Account lockout threshold <= 5`

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-05 · IAM 패스워드 정책 설정값 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-05",
  "name": "IAM 패스워드 정책 설정값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "IAM Password Policy",
    "MinimumPasswordLength",
    "RequireUppercaseCharacters",
    "RequireLowercaseCharacters",
    "RequireNumbers",
    "RequireSymbols",
    "PasswordReusePrevention",
    "MaxPasswordAge",
    "AllowUsersToChangePassword"
  ],
  "collection_command": "aws iam get-account-password-policy",
  "compliance_indicators": [
    {
      "field": "MinimumPasswordLength",
      "op": ">=",
      "value": 10
    },
    {
      "field": "RequireUppercaseCharacters",
      "op": "==",
      "value": true
    },
    {
      "field": "RequireLowercaseCharacters",
      "op": "==",
      "value": true
    },
    {
      "field": "RequireNumbers",
      "op": "==",
      "value": true
    },
    {
      "field": "RequireSymbols",
      "op": "==",
      "value": true
    },
    {
      "field": "MaxPasswordAge",
      "op": "<=",
      "value": 180
    },
    {
      "field": "PasswordReusePrevention",
      "op": ">=",
      "value": 4
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'IAM 패스워드 정책 설정값 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `MinimumPasswordLength`, `RequireUppercaseCharacters`, `RequireLowercaseCharacters`, `RequireNumbers`, `RequireSymbols`, `MaxPasswordAge`, `PasswordReusePrevention`
  - 판정 기준: `MinimumPasswordLength >= 10`; `RequireUppercaseCharacters == True`; `RequireLowercaseCharacters == True`; `RequireNumbers == True`; `RequireSymbols == True`; `MaxPasswordAge <= 180`; `PasswordReusePrevention >= 4`

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-06 · DB 패스워드 정책 설정값 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-06",
  "name": "DB 패스워드 정책 설정값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "CREATE PROFILE",
    "PASSWORD_LIFE_TIME",
    "PASSWORD_REUSE_TIME",
    "PASSWORD_REUSE_MAX",
    "FAILED_LOGIN_ATTEMPTS",
    "PASSWORD_LOCK_TIME",
    "PASSWORD_VERIFY_FUNCTION",
    "validate_password.policy",
    "validate_password.length"
  ],
  "compliance_indicators": [
    {
      "field": "PASSWORD_LIFE_TIME",
      "op": "<=",
      "value": 180,
      "unit": "days"
    },
    {
      "field": "FAILED_LOGIN_ATTEMPTS",
      "op": "<=",
      "value": 5
    },
    {
      "field": "PASSWORD_VERIFY_FUNCTION",
      "op": "!=",
      "value": null,
      "description": "검증 함수 활성화"
    },
    {
      "field": "validate_password.policy",
      "op": "==",
      "value": "STRONG"
    },
    {
      "field": "validate_password.length",
      "op": ">=",
      "value": 8
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'DB 패스워드 정책 설정값 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `PASSWORD_LIFE_TIME`, `FAILED_LOGIN_ATTEMPTS`, `PASSWORD_VERIFY_FUNCTION`, `validate_password.policy`, `validate_password.length`
  - 판정 기준: `PASSWORD_LIFE_TIME <= 180days`; `FAILED_LOGIN_ATTEMPTS <= 5`; `validate_password.policy == STRONG`; `validate_password.length >= 8`

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-07 · WAS 패스워드 정책 설정값 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-07",
  "name": "WAS 패스워드 정책 설정값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "Admin Console",
    "Security Realm",
    "Password Validation Provider",
    "Authentication Provider",
    "User Lockout",
    "Lockout Threshold",
    "Lockout Duration"
  ],
  "compliance_indicators": [
    {
      "field": "Password Validation Provider",
      "op": "==",
      "value": "Enabled"
    },
    {
      "field": "Lockout Threshold",
      "op": "<=",
      "value": 5
    },
    {
      "field": "Lockout Duration",
      "op": ">=",
      "value": 30,
      "unit": "minutes"
    },
    {
      "field": "Minimum Length",
      "op": ">=",
      "value": 8
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'WAS 패스워드 정책 설정값 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `Password Validation Provider`, `Lockout Threshold`, `Lockout Duration`, `Minimum Length`
  - 판정 기준: `Password Validation Provider == Enabled`; `Lockout Threshold <= 5`; `Lockout Duration >= 30minutes`; `Minimum Length >= 8`

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-08 · 회원가입·비밀번호 변경 화면 강제화 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-08",
  "name": "회원가입·비밀번호 변경 화면 강제화 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "회원가입",
    "Sign up",
    "Register",
    "비밀번호 변경",
    "Change Password",
    "비밀번호",
    "Password",
    "비밀번호 확인",
    "Confirm Password",
    "8자 이상",
    "10자 이상",
    "영문, 숫자, 특수문자",
    "at least N characters"
  ],
  "compliance_indicators": [
    {
      "pattern": "비밀번호는 최소 10자 이상",
      "type": "semantic_match"
    },
    {
      "pattern": "특수문자를 포함해야 합니다",
      "type": "semantic_match"
    },
    {
      "pattern": "must contain at least one symbol",
      "type": "semantic_match"
    },
    {
      "pattern": "password too short",
      "type": "semantic_match"
    },
    {
      "pattern": "강도 표시 (약함/강함)",
      "type": "ui_element"
    },
    {
      "description": "짧은 비밀번호 입력 시 가입 거부 동작"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "vlm_behavioral_analysis",
    "min_compliance_signals": 3,
    "any_deficiency_fails": true
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '회원가입·비밀번호 변경 화면 강제화 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-09 · 비밀번호 변경주기 준수 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-09",
  "name": "비밀번호 변경주기 준수 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "User ID",
    "사용자 ID",
    "Account",
    "Last password change",
    "Password Last Set",
    "최종 변경일자",
    "Days since change",
    "변경 후 경과일",
    "Age (days)",
    "Status",
    "상태"
  ],
  "collection_commands": [
    "Get-ADUser -Properties PasswordLastSet",
    "chage -l <user>",
    "aws iam get-credential-report",
    "SELECT username, last_password_change FROM ..."
  ],
  "compliance_indicators": [
    {
      "field": "days_since_change",
      "op": "<",
      "value": 180,
      "description": "반기 이내 변경"
    },
    {
      "description": "모든 활성 계정에 변경일 존재"
    },
    {
      "description": "변경주기 도래 시 강제 변경 로그 확인"
    }
  ],
  "judgment_logic": {
    "type": "aggregated_statistics",
    "method": "per_account_check",
    "violation_threshold_pct": 5,
    "description": "전체 계정의 5% 이상이 위반 시 미준수"
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '비밀번호 변경주기 준수 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `days_since_change`
  - 판정 기준: `days_since_change < 180`

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-10 · 임시 비밀번호 강제 변경 코드 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-10",
  "name": "임시 비밀번호 강제 변경 코드 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "isTemporary",
    "temp_password",
    "must_change_password",
    "password_reset_required",
    "forceChangePassword",
    "firstLogin",
    "pwd_change_required",
    "redirect('/change-password')"
  ],
  "compliance_indicators": [
    {
      "pattern": "if (user.tempPassword) → redirect to change",
      "type": "code_pattern"
    },
    {
      "pattern": "임시 비번 발급 시 expires_at 단기 설정",
      "type": "code_pattern"
    },
    {
      "description": "강제 변경 후에만 정상 세션 발급"
    }
  ],
  "judgment_logic": {
    "type": "code_pattern_match",
    "method": "regex_and_ast",
    "required_patterns": [
      "temp_flag_check",
      "redirect_to_change",
      "session_block_until_change"
    ],
    "min_patterns": 2
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '임시 비밀번호 강제 변경 코드 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-11 · 임시 비밀번호 강제 변경 화면 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-11",
  "name": "임시 비밀번호 강제 변경 화면 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "임시 비밀번호로 로그인하셨습니다",
    "비밀번호를 변경해 주세요",
    "You must change your password before continuing",
    "최초 로그인"
  ],
  "compliance_indicators": [
    {
      "description": "임시 비번 로그인 후 강제로 변경 화면으로 redirect"
    },
    {
      "description": "변경 전까지 다른 페이지 접근 불가"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "vlm_behavioral_analysis",
    "any_deficiency_fails": true
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '임시 비밀번호 강제 변경 화면 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-12 · 임시 비밀번호 미변경자 목록 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-12",
  "name": "임시 비밀번호 미변경자 목록 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "발급일",
    "Issued date",
    "발급 후 경과일",
    "미변경 계정",
    "Not yet changed",
    "Temp password issued but not changed"
  ],
  "compliance_indicators": [
    {
      "description": "미변경자 0명"
    },
    {
      "description": "최근 발급 24시간 이내 사례만 존재"
    },
    {
      "description": "미변경 시 자동 잠금 정책 존재"
    }
  ],
  "judgment_logic": {
    "type": "aggregated_statistics",
    "method": "count_violations",
    "max_violations": 0,
    "grace_period_hours": 24
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '임시 비밀번호 미변경자 목록 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-13 · DB 비밀번호 저장 형태 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-13",
  "name": "DB 비밀번호 저장 형태 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "password",
    "passwd",
    "pwd",
    "password_hash",
    "encrypted_password",
    "pw_hash",
    "salt",
    "iteration_count",
    "hash_algorithm"
  ],
  "compliance_indicators": [
    {
      "pattern": "^\\$2[aby]\\$",
      "type": "regex",
      "description": "bcrypt"
    },
    {
      "pattern": "^\\$argon2(i|id)\\$",
      "type": "regex",
      "description": "argon2"
    },
    {
      "pattern": "^\\$scrypt\\$|^\\$s0\\$",
      "type": "regex",
      "description": "scrypt"
    },
    {
      "pattern": "^pbkdf2_sha(256|512)\\$",
      "type": "regex",
      "description": "PBKDF2"
    },
    {
      "description": "SHA-256/512 + salt 컬럼 동반 (64/128 hex)"
    }
  ],
  "judgment_logic": {
    "type": "regex_match",
    "method": "any_sample_violation_fails",
    "sample_size_min": 10,
    "description": "샘플 중 하나라도 결함 패턴 매칭 시 미준수"
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'DB 비밀번호 저장 형태 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-14 · MFA 설정 정책 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-14",
  "name": "MFA 설정 정책 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "MFA",
    "Multi-Factor Authentication",
    "2FA",
    "Two-Factor",
    "이중 인증",
    "다중 인증",
    "다단계 인증",
    "Enforced",
    "Required",
    "필수",
    "Optional",
    "선택",
    "Enabled",
    "Disabled",
    "OTP",
    "TOTP",
    "Authenticator app",
    "Google Authenticator",
    "Security key",
    "YubiKey",
    "SMS",
    "Email",
    "생체인증",
    "지문",
    "Face ID",
    "인증서",
    "보안토큰",
    "일회용 비밀번호"
  ],
  "compliance_indicators": [
    {
      "pattern": "MFA Required for all users",
      "type": "semantic_match"
    },
    {
      "pattern": "Admin MFA enforced",
      "type": "semantic_match"
    },
    {
      "pattern": "관리자 계정 MFA 필수",
      "type": "semantic_match"
    },
    {
      "description": "외부 접속 시 OTP 입력 화면 존재"
    },
    {
      "description": "인증수단별 적용 대상 명시 (관리자=하드웨어 토큰, 일반=TOTP 등)"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "admin_mfa_required_and_all_users_recommended",
    "critical_fields": [
      "Admin MFA"
    ]
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'MFA 설정 정책 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-15 · 로그인 화면 인증수단 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-15",
  "name": "로그인 화면 인증수단 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "keywords": [
    "Login",
    "Sign in",
    "로그인",
    "Username",
    "ID",
    "아이디",
    "Password",
    "비밀번호",
    "OTP 입력란",
    "인증 앱 코드",
    "SMS 코드"
  ],
  "compliance_indicators": [
    {
      "pattern": "아이디 또는 비밀번호가 일치하지 않습니다",
      "type": "exact_match",
      "description": "generic 실패 메시지"
    },
    {
      "pattern": "Invalid credentials",
      "type": "exact_match"
    },
    {
      "pattern": "Login failed",
      "type": "exact_match"
    },
    {
      "pattern": "계정이 잠겼습니다",
      "type": "semantic_match"
    },
    {
      "pattern": "5회 실패로 잠금",
      "type": "semantic_match"
    },
    {
      "pattern": "Account locked",
      "type": "semantic_match"
    },
    {
      "description": "2단계 인증 단계 존재"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "vlm_behavioral_analysis",
    "any_deficiency_fails": true,
    "min_compliance_signals": 2
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '로그인 화면 인증수단 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - 해당 리소스 상태

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL01 · 비밀번호 관리 정책 문서가 존재하고 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL01",
  "name": "비밀번호 관리 정책 문서가 존재하고 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호 관리 정책 문서가 존재하며 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "지침서에 비밀번호 생성규칙, 변경주기, 저장방법이 모두 명시"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호 관리 정책 문서가 존재하고 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호 관리 정책 문서가 존재하며 비밀번호 생성 규칙·변경 주기·저장 방법을 포함하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL02 · 비밀번호 최소 길이를 8자 이상으로 설정하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL02",
  "name": "비밀번호 최소 길이를 8자 이상으로 설정하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호 최소 길이를 8자 이상으로 설정하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "field": "최소길이",
      "op": ">=",
      "value": 8,
      "description": "비밀번호 최소 8자 이상 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호 최소 길이를 8자 이상으로 설정하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호 최소 길이를 8자 이상으로 설정하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL03 · 비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL03",
  "name": "비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "field": "최대사용일수",
      "op": "<=",
      "value": 90,
      "description": "비밀번호 최대 사용기간 90일 이하 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호 최대 사용 기간을 90일 이하로 설정하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL04 · 초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL04",
  "name": "초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "초기/임시 비밀번호 발급 시 최초 로그인 시 강제 변경 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「초기(임시) 비밀번호 발급 시 최초 로그인 시 변경을 강제하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL05 · 비밀번호를 일방향 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL05",
  "name": "비밀번호를 일방향 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호를 일방향(단방향) 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "비밀번호 일방향 암호화 저장 및 평문 저장 금지 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호를 일방향 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호를 일방향(단방향) 암호화(bcrypt, argon2, PBKDF2 등)하여 저장하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL06 · 비밀번호 입력 오류 시 계정 잠금 처리하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL06",
  "name": "비밀번호 입력 오류 시 계정 잠금 처리하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호 입력 오류가 일정 횟수 누적되면 계정을 잠금 처리하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "field": "잠금횟수",
      "op": "<=",
      "value": 5,
      "description": "5회 이내 입력 오류 시 계정 잠금 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호 입력 오류 시 계정 잠금 처리하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호 입력 오류가 일정 횟수 누적되면 계정을 잠금 처리하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL07 · 관리자 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL07",
  "name": "관리자 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "관리자 계정 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "관리자·중요 시스템 접근 시 다중인증(MFA) 적용 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'관리자 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「관리자 계정 및 중요 시스템 접근 시 다중인증(MFA)을 적용하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL08 · 로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL08",
  "name": "로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "로그인 실패 시 아이디·비밀번호 구분 정보 미노출 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「로그인 실패 메시지에서 아이디·비밀번호 구분 노출을 금지하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL09 · 추측하기 쉬운 비밀번호 사용 금지
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 WR-02(추측금지) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL09",
  "name": "추측하기 쉬운 비밀번호 사용 금지",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "생일·전화번호·아이디처럼 추측하기 쉬운 비밀번호를 쓰지 못하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "추측하기 쉬운 비밀번호 사용 금지 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'추측하기 쉬운 비밀번호 사용 금지'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「생일·전화번호·아이디처럼 추측하기 쉬운 비밀번호를 쓰지 못하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL10 · 반복·연속 문자 비밀번호 제한
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 WR-03(반복·연속) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL10",
  "name": "반복·연속 문자 비밀번호 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "같은 문자 반복이나 연속된 숫자로 된 비밀번호를 제한하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "반복·연속 문자 비밀번호 제한 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'반복·연속 문자 비밀번호 제한'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「같은 문자 반복이나 연속된 숫자로 된 비밀번호를 제한하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL11 · 비밀번호 입력 시 화면 가림(마스킹)
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 MP-02(마스킹) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL11",
  "name": "비밀번호 입력 시 화면 가림(마스킹)",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호를 입력하거나 변경할 때 화면에 마스킹 처리하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "비밀번호 입력 시 화면 가림(마스킹) 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호 입력 시 화면 가림(마스킹)'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호를 입력하거나 변경할 때 화면에 마스킹 처리하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL12 · 비밀번호 기록·보관 제한
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 MP-03(기록·보관) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL12",
  "name": "비밀번호 기록·보관 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호를 종이·파일·모바일 등에 기록·보관하는 것을 제한하고 부득이하면 암호화하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "비밀번호 기록·보관 제한 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비밀번호 기록·보관 제한'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호를 종이·파일·모바일 등에 기록·보관하는 것을 제한하고 부득이하면 암호화하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL13 · 유출 의심 시 즉시 변경
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 MP-04(유출 시 변경) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL13",
  "name": "유출 의심 시 즉시 변경",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호 노출이나 침해가 의심되면 지체 없이 변경하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "유출 의심 시 즉시 변경 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'유출 의심 시 즉시 변경'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호 노출이나 침해가 의심되면 지체 없이 변경하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL14 · 분실 시 본인확인 후 재발급
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 MP-05(분실 재발급) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL14",
  "name": "분실 시 본인확인 후 재발급",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "비밀번호 분실 시 본인 확인을 거쳐 안전하게 재발급하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "분실 시 본인확인 후 재발급 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'분실 시 본인확인 후 재발급'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「비밀번호 분실 시 본인 확인을 거쳐 안전하게 재발급하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

## R-2.5.4-GL15 · 관리자 비밀번호 별도 강화 관리
*📄 지침·정책 점검(문장기반 RAG)*
> 🆕 신규: 구 R-2.5.4-02 MP-07(관리자 별도) 이관

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.4-GL15",
  "name": "관리자 비밀번호 별도 강화 관리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "관리자 비밀번호는 일반 사용자와 분리해 더 강한 기준으로 관리하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "관리자 비밀번호 별도 강화 관리 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'관리자 비밀번호 별도 강화 관리'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「관리자 비밀번호는 일반 사용자와 분리해 더 강한 기준으로 관리하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.4 비밀번호 관리** 인증기준: "법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보의 안전성 확보조치 기준 제5조제5항, 개인정보의 안전성 확보조치 기준 제7조제1항, 개인정보의 기술적·관리적 보호조치 기준 제4조제8항)

---

# 2.5.5 특수 계정 및 권한 관리

## F-2.5.5-01 · 클러스터 최고 권한 보유 SA 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.5.5-01",
  "name": "클러스터 최고 권한 보유 SA 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount + RBAC chain",
    "required_data": [
      "cluster_pods.service_account",
      "cluster_role_bindings",
      "cluster_cluster_role_bindings",
      "cluster_roles",
      "cluster_cluster_roles"
    ],
    "condition": {
      "operator": "any_of",
      "conditions": [
        {
          "binding_target": "cluster-admin"
        },
        {
          "rules_contain": {
            "verbs": [
              "*"
            ],
            "resources": [
              "*"
            ]
          }
        },
        {
          "cluster_scope_secret_access": [
            "get",
            "list",
            "watch"
          ]
        }
      ]
    },
    "manual_check_areas": [
      "권한 부여 결재 기록"
    ]
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.service_account`, `cluster_role_bindings`, `cluster_cluster_role_bindings`, `cluster_roles`, `cluster_cluster_roles`
  - 사람 검토 영역: 권한 부여 결재 기록

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## F-2.5.5-02 · 위험 RBAC 권한 보유 SA 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.5.5-02",
  "name": "위험 RBAC 권한 보유 SA 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "ServiceAccount + RBAC chain",
    "required_data": [
      "cluster_role_bindings",
      "cluster_cluster_role_bindings",
      "cluster_roles",
      "cluster_cluster_roles"
    ],
    "condition": {
      "operator": "any_dangerous_verb",
      "patterns": [
        {
          "name": "pod_exec",
          "resource": "pods/exec",
          "verbs": [
            "create",
            "*"
          ]
        },
        {
          "name": "secret_write",
          "resource": "secrets",
          "verbs": [
            "create",
            "update",
            "patch",
            "*"
          ]
        },
        {
          "name": "rbac_escalate",
          "resource": "*",
          "verbs": [
            "escalate"
          ]
        },
        {
          "name": "impersonate",
          "resource": "users|groups|serviceaccounts",
          "verbs": [
            "impersonate"
          ]
        }
      ]
    },
    "manual_check_areas": [
      "RBAC 정책 문서 확인",
      "권한 부여 결재 기록"
    ]
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_role_bindings`, `cluster_cluster_role_bindings`, `cluster_roles`, `cluster_cluster_roles`
  - 사람 검토 영역: RBAC 정책 문서 확인, 권한 부여 결재 기록

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-01 · ServiceAccount 특수 권한 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-01",
  "name": "ServiceAccount 특수 권한 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "has_cluster_admin",
      "op": "==",
      "value": false,
      "description": "cluster-admin 바인딩 없음"
    },
    {
      "field": "has_wildcard_permission",
      "op": "==",
      "value": false,
      "description": "verbs:* + resources:* 와일드카드 권한 없음"
    },
    {
      "field": "has_cluster_wide_secrets",
      "op": "==",
      "value": false,
      "description": "클러스터 전체 Secret 접근 권한 없음"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required"
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'ServiceAccount 특수 권한 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_roles`·`cluster_role_bindings`·`cluster_cluster_roles`·`cluster_cluster_role_bindings` (rules·role_ref·subjects JSONB)
  - 판정 기준: `has_cluster_admin == False`; `has_wildcard_permission == False`; `has_cluster_wide_secrets == False`

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-02 · 위험 RBAC verb 조합 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-02",
  "name": "위험 RBAC verb 조합 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "dangerous_verb_combinations": [
    {
      "name": "pod_exec_attach",
      "verbs": [
        "create",
        "get"
      ],
      "resources": [
        "pods/exec",
        "pods/attach",
        "pods/portforward"
      ],
      "risk": "컨테이너 내부 임의 명령 실행"
    },
    {
      "name": "secret_read_cluster_wide",
      "verbs": [
        "get",
        "list",
        "watch"
      ],
      "resources": [
        "secrets"
      ],
      "scope": "cluster_wide",
      "risk": "클러스터 전체 비밀정보 열람"
    },
    {
      "name": "secret_write",
      "verbs": [
        "create",
        "update",
        "patch",
        "delete"
      ],
      "resources": [
        "secrets"
      ],
      "risk": "비밀정보 변조·삭제"
    },
    {
      "name": "rbac_escalate",
      "verbs": [
        "escalate"
      ],
      "resources": [
        "clusterroles",
        "roles"
      ],
      "risk": "RBAC 권한 자체 상승"
    },
    {
      "name": "rbac_bind",
      "verbs": [
        "bind"
      ],
      "resources": [
        "clusterroles",
        "roles"
      ],
      "risk": "임의 권한 바인딩"
    },
    {
      "name": "impersonate",
      "verbs": [
        "impersonate"
      ],
      "resources": [
        "users",
        "groups",
        "serviceaccounts"
      ],
      "risk": "다른 계정 가장하여 API 호출"
    },
    {
      "name": "node_proxy",
      "verbs": [
        "get",
        "create"
      ],
      "resources": [
        "nodes/proxy"
      ],
      "risk": "kubelet API 직접 접근"
    },
    {
      "name": "sa_token_request",
      "verbs": [
        "create"
      ],
      "resources": [
        "serviceaccounts/token"
      ],
      "risk": "임의 ServiceAccount 토큰 발급"
    }
  ],
  "compliance_indicators": [
    {
      "field": "has_dangerous_verb_combo",
      "op": "==",
      "value": false,
      "description": "위험 verb 조합 미보유"
    }
  ],
  "exception_check": {
    "annotation": "rbac-exception/justification",
    "system_namespaces": [
      "kube-system",
      "kube-node-lease"
    ]
  },
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required"
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '위험 RBAC verb 조합 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_roles`·`cluster_role_bindings`·`cluster_cluster_roles`·`cluster_cluster_role_bindings` (rules·role_ref·subjects JSONB)
  - 판정 기준: `has_dangerous_verb_combo == False`

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-GL01 · 특수 권한 현황을 정기적으로 검토하고 불필요한 권한을 회수하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-GL01",
  "name": "특수 권한 현황을 정기적으로 검토하고 불필요한 권한을 회수하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "특수 권한 현황을 분기 이내 주기로 정기 검토하고 불필요한 권한을 회수하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "field": "검토주기",
      "op": "<=",
      "value": "분기",
      "description": "특수 권한 검토 주기를 분기 이내로 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'특수 권한 현황을 정기적으로 검토하고 불필요한 권한을 회수하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「특수 권한 현황을 분기 이내 주기로 정기 검토하고 불필요한 권한을 회수하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-GL02 · 불필요한 특수 권한을 즉시 회수하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-GL02",
  "name": "불필요한 특수 권한을 즉시 회수하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "불필요한 특수 권한을 발견 즉시 회수하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "불필요한 특수 권한 발견 시 즉시 회수 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'불필요한 특수 권한을 즉시 회수하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「불필요한 특수 권한을 발견 즉시 회수하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-GL03 · 특수 계정 사용 시 책임추적성(로깅·감사)을 확보하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-GL03",
  "name": "특수 계정 사용 시 책임추적성(로깅·감사)을 확보하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "특수 계정 사용 시 로그 기록 및 감사를 통해 책임추적성을 확보하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "특수 계정 사용 시 로그 기록 및 감사 수행 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'특수 계정 사용 시 책임추적성(로깅·감사)을 확보하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「특수 계정 사용 시 로그 기록 및 감사를 통해 책임추적성을 확보하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-GL04 · 특수 계정 목록을 최신 상태로 관리하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-GL04",
  "name": "특수 계정 목록을 최신 상태로 관리하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "특수 계정 목록을 별도로 식별하여 최신 상태로 관리하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "특수 계정 목록을 최신 상태로 유지·관리 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'특수 계정 목록을 최신 상태로 관리하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「특수 계정 목록을 별도로 식별하여 최신 상태로 관리하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-GL05 · 특수 권한 부여 시 승인 절차를 거치도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-GL05",
  "name": "특수 권한 부여 시 승인 절차를 거치도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "특수 권한 부여 시 신청·승인(결재) 절차를 거치도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "특수 권한 부여 시 승인 절차(신청·결재) 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'특수 권한 부여 시 승인 절차를 거치도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「특수 권한 부여 시 신청·승인(결재) 절차를 거치도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

## R-2.5.5-GL06 · 특수 계정의 공동 사용을 금지하도록 규정
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.5.5-GL06",
  "name": "특수 계정의 공동 사용을 금지하도록 규정",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "특수 계정의 공동 사용을 금지하고 개인별로 계정을 부여하도록 규정한다."
  ],
  "compliance_indicators": [
    {
      "description": "특수 계정의 공동 사용 금지 및 개인별 계정 부여 규정"
    }
  ],
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment"
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'특수 계정의 공동 사용을 금지하도록 규정'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「특수 계정의 공동 사용을 금지하고 개인별로 계정을 부여하도록 규정한다.」

**④ 당위성**
ISMS-P **2.5.5 특수 계정 및 권한 관리** 인증기준: "정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조)

---

# 2.6.1 네트워크 접근

## F-2.6.1-01 · NetworkPolicy 적용 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.6.1-01",
  "name": "NetworkPolicy 적용 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Namespace + NetworkPolicy",
    "required_data": [
      "cluster_namespaces",
      "cluster_network_policies"
    ],
    "condition": {
      "operator": "default_deny_coverage_report"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.1",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "서버팜과 사무망 미분리",
        "match": "partial"
      }
    ],
    "additional_review_items": [
      "K8s NetworkPolicy 외 네트워크 분리 통제가 적용되어 있는가",
      "미적용 namespace가 인증범위 내인가",
      "운영망/개발망/DMZ 등 영역별 분리 설계"
    ],
    "manual_check_areas": [
      "네트워크 분리 설계 문서",
      "VPC/Subnet/Security Group 정책",
      "사내망 IP 관리 대장"
    ],
    "automation_coverage": {
      "percentage": 40,
      "covered": "K8s NetworkPolicy 적용 현황",
      "not_covered": "K8s 외 네트워크 통제, 사내망 단말 인증"
    },
    "alternative_controls": [
      "VPC subnet 분리 + Security Group",
      "Istio AuthorizationPolicy",
      "Calico GlobalNetworkPolicy",
      "별도 클러스터 운영"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_namespaces`, `cluster_network_policies`
  - 사람 검토 영역: 네트워크 분리 설계 문서, VPC/Subnet/Security Group 정책, 사내망 IP 관리 대장

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## F-2.6.1-02 · CNI NetworkPolicy 강제 상태
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.6.1-02",
  "name": "CNI NetworkPolicy 강제 상태",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Cluster Workload",
    "required_data": [
      "cluster_workloads"
    ],
    "condition": {
      "operator": "daemonset_exists",
      "namespace": "kube-system",
      "name_patterns": [
        "calico-node",
        "cilium",
        "calico-kube-controllers"
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.1",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "미발견 시 K8s NetworkPolicy 무효화 가능성 - 외부 통제로 분리 확인",
      "발견 시 정책 강제 옵션 활성화 여부(도구는 옵션 미확인)"
    ],
    "manual_check_areas": [
      "CNI 설정 문서",
      "Network 강제 정책 운영 상태"
    ],
    "automation_coverage": {
      "percentage": 50,
      "covered": "CNI 배포 여부",
      "not_covered": "정책 강제 옵션 활성화 상태"
    },
    "alternative_controls": [
      "AWS VPC CNI + Security Group",
      "Service Mesh",
      "외부 NetFW"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_workloads`
  - 사람 검토 영역: CNI 설정 문서, Network 강제 정책 운영 상태

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## F-2.6.1-03 · Cross-namespace 통신 통제 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.6.1-03",
  "name": "Cross-namespace 통신 통제 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "NetworkPolicy + Namespace",
    "required_data": [
      "cluster_network_policies",
      "cluster_namespaces",
      "cluster_pods"
    ],
    "condition": {
      "operator": "cross_ns_traffic_control_report"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.1",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "영역별 분리가 cluster 또는 VPC 분리로 이뤄지면 K8s 통제 불필요",
      "단일 클러스터 내 영역 분리라면 K8s 통제 적용 권장"
    ],
    "manual_check_areas": [
      "네트워크 분리 설계 문서",
      "VPC 분리 정책"
    ],
    "automation_coverage": {
      "percentage": 50,
      "covered": "K8s NetworkPolicy 차원의 cross-ns 통제",
      "not_covered": "VPC/Service Mesh 차원의 통제"
    },
    "alternative_controls": [
      "VPC 라우팅",
      "Service Mesh",
      "별도 클러스터"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_network_policies`, `cluster_namespaces`, `cluster_pods`
  - 사람 검토 영역: 네트워크 분리 설계 문서, VPC 분리 정책

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-01 · hostNetwork 사용 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-01",
  "name": "hostNetwork 사용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "pod.spec.hostNetwork",
      "op": "!=",
      "value": true,
      "description": "hostNetwork 비활성"
    },
    {
      "field": "pod.spec.hostPID",
      "op": "!=",
      "value": true,
      "description": "hostPID 비활성"
    },
    {
      "field": "pod.spec.hostIPC",
      "op": "!=",
      "value": true,
      "description": "hostIPC 비활성"
    }
  ],
  "exception_check": {
    "annotation": "security-exception/justification",
    "system_namespaces": [
      "kube-system",
      "kube-node-lease",
      "amazon-cloudwatch"
    ]
  },
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'hostNetwork 사용 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.host_network` (BOOL)
  - 판정 기준: `pod.spec.hostNetwork != True`; `pod.spec.hostPID != True`; `pod.spec.hostIPC != True`

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-02 · NetworkPolicy 적용 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-02",
  "name": "NetworkPolicy 적용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "has_default_deny",
      "op": "==",
      "value": true,
      "description": "default-deny(Ingress+Egress) NetworkPolicy 존재"
    },
    {
      "field": "has_matching_policy",
      "op": "==",
      "value": true,
      "description": "Pod에 매칭되는 허용 NetworkPolicy 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'NetworkPolicy 적용 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_network_policies` (pod_selector, policy_types, ingress_rules, egress_rules JSONB)
  - 판정 기준: `has_default_deny == True`; `has_matching_policy == True`

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-03 · CNI NetworkPolicy 강제 지원 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-03",
  "name": "CNI NetworkPolicy 강제 지원 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "supported_cni_indicators": [
    {
      "name": "calico",
      "daemonset_name": "calico-node",
      "policy_enforcement": "native"
    },
    {
      "name": "cilium",
      "daemonset_name": "cilium",
      "policy_enforcement": "native"
    },
    {
      "name": "weave",
      "daemonset_name": "weave-net",
      "policy_enforcement": "native"
    },
    {
      "name": "aws-vpc-cni",
      "daemonset_name": "aws-node",
      "policy_enforcement": "conditional",
      "required_env": {
        "ENABLE_NETWORK_POLICY": "true"
      }
    }
  ],
  "compliance_indicators": [
    {
      "field": "has_policy_capable_cni",
      "op": "==",
      "value": true,
      "description": "NetworkPolicy 강제 가능한 CNI DaemonSet 존재"
    },
    {
      "field": "policy_enforcement_enabled",
      "op": "==",
      "value": true,
      "description": "aws-vpc-cni 경우 aws-node DaemonSet env에 ENABLE_NETWORK_POLICY=true 설정"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'CNI NetworkPolicy 강제 지원 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_workloads` (kind, selector, template_labels JSONB, containers JSONB)
  - 판정 기준: `has_policy_capable_cni == True`; `policy_enforcement_enabled == True`

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-04 · cross-namespace 통신 통제 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-04",
  "name": "cross-namespace 통신 통제 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "cross_ns_egress_controlled",
      "op": "==",
      "value": true,
      "description": "Pod에 매칭되는 egress NetworkPolicy로 cross-namespace 통신 통제"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'cross-namespace 통신 통제 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_network_policies` (pod_selector, policy_types, ingress_rules, egress_rules JSONB)
  - 판정 기준: `cross_ns_egress_controlled == True`

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-GL01 · 비인가 네트워크 접근 통제 절차
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-GL01",
  "name": "비인가 네트워크 접근 통제 절차",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "네트워크에 대한 비인가 접근을 통제하기 위해 IP 관리, 단말 인증 등 관리절차를 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "IP 관리·단말 인증 등 비인가 네트워크 접근 통제 절차를 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'비인가 네트워크 접근 통제 절차'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「네트워크에 대한 비인가 접근을 통제하기 위해 IP 관리, 단말 인증 등 관리절차를 수립·이행한다.」

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-GL02 · IP 부여 기준 및 사설 IP 할당
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-GL02",
  "name": "IP 부여 기준 및 사설 IP 할당",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "네트워크 대역별 IP 주소 부여 기준을 마련하고, 외부 연결이 필요하지 않은 시스템(DB 서버 등)에는 사설 IP를 할당한다."
  ],
  "compliance_indicators": [
    {
      "description": "대역별 IP 부여 기준 마련 및 외부 연결 불필요 시스템의 사설 IP 할당을 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'IP 부여 기준 및 사설 IP 할당'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「네트워크 대역별 IP 주소 부여 기준을 마련하고, 외부 연결이 필요하지 않은 시스템(DB 서버 등)에는 사설 IP를 할당한다.」

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-GL03 · 업무 중요도 기반 네트워크 분리
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-GL03",
  "name": "업무 중요도 기반 네트워크 분리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "업무 목적 및 중요도에 따라 네트워크를 영역별(DMZ, 서버팜, DB존, 개발존 등)로 분리하고 접근통제를 적용한다."
  ],
  "compliance_indicators": [
    {
      "description": "업무 목적·중요도에 따라 네트워크를 영역별로 분리하고 접근통제를 적용하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'업무 중요도 기반 네트워크 분리'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「업무 목적 및 중요도에 따라 네트워크를 영역별(DMZ, 서버팜, DB존, 개발존 등)로 분리하고 접근통제를 적용한다.」

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.1-GL04 · 원거리 연결 전송구간 보호
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.1-GL04",
  "name": "원거리 연결 전송구간 보호",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "물리적으로 떨어진 IDC·지사·대리점 등과의 네트워크 연결 시 전송구간 보호대책을 마련한다."
  ],
  "compliance_indicators": [
    {
      "description": "원거리 네트워크 연결 시 전송구간 보호대책을 마련하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'원거리 연결 전송구간 보호'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「물리적으로 떨어진 IDC·지사·대리점 등과의 네트워크 연결 시 전송구간 보호대책을 마련한다.」

**④ 당위성**
ISMS-P **2.6.1 네트워크 접근** 인증기준: "네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

# 2.6.3 응용프로그램 접근

## R-2.6.3-01 · Ingress 인증 적용 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.3-01",
  "name": "Ingress 인증 적용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "auth_annotations": [
    "nginx.ingress.kubernetes.io/auth-type",
    "nginx.ingress.kubernetes.io/auth-url",
    "alb.ingress.kubernetes.io/auth-type",
    "traefik.ingress.kubernetes.io/auth-type"
  ],
  "compliance_indicators": [
    {
      "field": "all_ingresses_have_auth",
      "op": "==",
      "value": true,
      "description": "Pod에 연결된 모든 Ingress에 인증 설정 적용됨"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'Ingress 인증 적용 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `all_ingresses_have_auth == True`

**④ 당위성**
ISMS-P **2.6.3 응용프로그램 접근** 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.3-02 · 내부 Service mTLS 강제 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.3-02",
  "name": "내부 Service mTLS 강제 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "acceptable_mtls_modes": [
    "STRICT"
  ],
  "compliance_indicators": [
    {
      "field": "istio_injection_enabled",
      "op": "==",
      "value": true,
      "description": "namespace에 istio sidecar 자동 주입 활성"
    },
    {
      "field": "effective_mtls_mode",
      "op": "==",
      "value": "STRICT",
      "description": "namespace 또는 mesh-wide PeerAuthentication mtls.mode=STRICT 적용"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '내부 Service mTLS 강제 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_namespaces.namespace` (TEXT). ⚠️ 라벨 컬럼이 없어 namespace 라벨은 DB에 적재되지 않음 — assembler가 빈 값으로 채움(현 구조상 라벨 기반 판정 불가)
  - 판정 기준: `istio_injection_enabled == True`; `effective_mtls_mode == STRICT`

**④ 당위성**
ISMS-P **2.6.3 응용프로그램 접근** 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.3-GL01 · 응용프로그램 접근권한 제한
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.3-GL01",
  "name": "응용프로그램 접근권한 제한",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "사용자별 업무 및 정보의 중요도에 따라 응용프로그램 접근권한을 제한한다."
  ],
  "compliance_indicators": [
    {
      "description": "사용자별 업무·정보 중요도에 따라 응용프로그램 접근권한을 제한하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'응용프로그램 접근권한 제한'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「사용자별 업무 및 정보의 중요도에 따라 응용프로그램 접근권한을 제한한다.」

**④ 당위성**
ISMS-P **2.6.3 응용프로그램 접근** 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.3-GL02 · 표시제한 보호조치 기준 수립
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.3-GL02",
  "name": "표시제한 보호조치 기준 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "개인정보 및 중요정보의 표시제한 보호조치의 일관성을 확보할 수 있도록 관련 기준을 수립하여 적용한다."
  ],
  "compliance_indicators": [
    {
      "description": "개인정보·중요정보 표시제한 보호조치 기준을 수립·적용하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'표시제한 보호조치 기준 수립'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「개인정보 및 중요정보의 표시제한 보호조치의 일관성을 확보할 수 있도록 관련 기준을 수립하여 적용한다.」

**④ 당위성**
ISMS-P **2.6.3 응용프로그램 접근** 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.3-GL03 · 정보 노출 최소화
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.3-GL03",
  "name": "정보 노출 최소화",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "개인정보 및 중요정보의 불필요한 노출(조회, 화면표시, 인쇄, 다운로드 등)을 최소화하도록 응용프로그램을 구현·운영한다."
  ],
  "compliance_indicators": [
    {
      "description": "불필요한 정보 노출을 최소화하도록 응용프로그램을 구현·운영하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'정보 노출 최소화'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「개인정보 및 중요정보의 불필요한 노출(조회, 화면표시, 인쇄, 다운로드 등)을 최소화하도록 응용프로그램을 구현·운영한다.」

**④ 당위성**
ISMS-P **2.6.3 응용프로그램 접근** 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.3-GL04 · 세션 통제
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.3-GL04",
  "name": "세션 통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "동일 사용자의 동시 접속 세션 수를 제한하고 일정시간 미사용 시 세션을 자동 차단한다."
  ],
  "compliance_indicators": [
    {
      "description": "동시 세션 제한 및 미사용 세션 자동 차단을 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'세션 통제'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「동일 사용자의 동시 접속 세션 수를 제한하고 일정시간 미사용 시 세션을 자동 차단한다.」

**④ 당위성**
ISMS-P **2.6.3 응용프로그램 접근** 인증기준: "사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제5조, 개인정보의 안전성 확보조치 기준 제6조)

---

# 2.6.7 인터넷 접속 통제

## F-2.6.7-01 · Pod egress 통제 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.6.7-01",
  "name": "Pod egress 통제 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "needs_review",
  "manual_meta": {
    "target_resource": "Pod + NetworkPolicy",
    "required_data": [
      "cluster_pods",
      "cluster_network_policies"
    ],
    "condition": {
      "operator": "egress_policy_applied"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.7",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "운영 서버에서 외부 인터넷 자유 접속",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "K8s 외 VPC NAT Gateway 화이트리스트 적용 여부",
      "프록시 서버를 통한 외부 접속 통제",
      "발견된 Pod가 개인정보 처리 시스템인지"
    ],
    "manual_check_areas": [
      "외부 접속 화이트리스트 정책",
      "프록시 서버 운영 현황",
      "VPC 라우팅 정책"
    ],
    "automation_coverage": {
      "percentage": 40,
      "covered": "K8s NetworkPolicy 기반 통제",
      "not_covered": "VPC NAT, 프록시 등 외부 통제"
    },
    "alternative_controls": [
      "VPC NAT Gateway 화이트리스트",
      "프록시 서버(Squid 등)",
      "Cilium FQDN policy",
      "AWS Network Firewall"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods`, `cluster_network_policies`
  - 사람 검토 영역: 외부 접속 화이트리스트 정책, 프록시 서버 운영 현황, VPC 라우팅 정책

**④ 당위성**
ISMS-P **2.6.7 인터넷 접속 통제** 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## F-2.6.7-02 · 실제 외부 도메인 접속 관찰 (eBPF)
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.6.7-02",
  "name": "실제 외부 도메인 접속 관찰 (eBPF)",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "compliant_indicator",
  "manual_meta": {
    "target_resource": "eBPF DNS queries",
    "required_data": [
      "ebpf_dns_queries",
      "cluster_pods"
    ],
    "condition": {
      "operator": "external_domain_traffic_report",
      "time_window": "24h"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.7",
        "match_strength": "supportive"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "화이트리스트와 실제 접속 패턴 일치 여부",
      "의심 도메인 접속이 있는가",
      "개인정보 처리 Pod의 외부 접속 패턴 검토"
    ],
    "manual_check_areas": [
      "외부 접속 화이트리스트",
      "DNS 로그 분석 기록"
    ],
    "automation_coverage": {
      "percentage": 80,
      "covered": "실제 통신 패턴 관찰",
      "not_covered": "통제 정책 자체"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `ebpf_dns_queries`, `cluster_pods`
  - 사람 검토 영역: 외부 접속 화이트리스트, DNS 로그 분석 기록

**④ 당위성**
ISMS-P **2.6.7 인터넷 접속 통제** 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.7-01 · egress NetworkPolicy 미적용
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.7-01",
  "name": "egress NetworkPolicy 미적용",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "has_egress_policy",
      "op": "==",
      "value": true,
      "description": "Pod에 매칭되는 Egress NetworkPolicy 존재 — 아웃바운드 트래픽 통제 적용"
    },
    {
      "field": "egress_default_deny_exists",
      "op": "==",
      "value": true,
      "description": "namespace에 Egress default-deny NetworkPolicy 존재"
    }
  ],
  "exception_check": {
    "annotation": "security-exception/egress-justification",
    "system_namespaces": [
      "kube-system",
      "kube-node-lease",
      "amazon-cloudwatch"
    ]
  },
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'egress NetworkPolicy 미적용' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_network_policies` (pod_selector, policy_types, ingress_rules, egress_rules JSONB)
  - 판정 기준: `has_egress_policy == True`; `egress_default_deny_exists == True`

**④ 당위성**
ISMS-P **2.6.7 인터넷 접속 통제** 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.7-GL01 · 인터넷 접속 통제 정책 수립
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.7-GL01",
  "name": "인터넷 접속 통제 정책 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "업무용 단말기 등에서 인터넷 접속 시 정보유출 등 보안사고를 예방하기 위한 인터넷 접속 통제 정책을 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "인터넷 접속 통제 정책을 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.7",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'인터넷 접속 통제 정책 수립'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「업무용 단말기 등에서 인터넷 접속 시 정보유출 등 보안사고를 예방하기 위한 인터넷 접속 통제 정책을 수립·이행한다.」

**④ 당위성**
ISMS-P **2.6.7 인터넷 접속 통제** 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.7-GL02 · 주요 시스템 외부 인터넷 접속 통제
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.7-GL02",
  "name": "주요 시스템 외부 인터넷 접속 통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "주요 정보시스템(DB 서버 등)에서 불필요한 외부 인터넷 접속을 통제한다."
  ],
  "compliance_indicators": [
    {
      "description": "주요 정보시스템의 불필요한 외부 인터넷 접속을 통제하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.7",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'주요 시스템 외부 인터넷 접속 통제'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「주요 정보시스템(DB 서버 등)에서 불필요한 외부 인터넷 접속을 통제한다.」

**④ 당위성**
ISMS-P **2.6.7 인터넷 접속 통제** 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

## R-2.6.7-GL03 · 인터넷망 차단 의무 이행
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.6.7-GL03",
  "name": "인터넷망 차단 의무 이행",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "관련 법령에 따라 인터넷망 차단 의무가 부과된 경우 대상자를 식별하여 안전한 방식으로 인터넷망 차단 조치를 적용한다."
  ],
  "compliance_indicators": [
    {
      "description": "법령상 인터넷망 차단 의무 대상자를 식별하고 차단 조치를 적용하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.6.7",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'인터넷망 차단 의무 이행'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「관련 법령에 따라 인터넷망 차단 의무가 부과된 경우 대상자를 식별하여 안전한 방식으로 인터넷망 차단 조치를 적용한다.」

**④ 당위성**
ISMS-P **2.6.7 인터넷 접속 통제** 인증기준: "업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제6조)

---

# 2.7.1 암호정책 적용

## F-2.7.1-01 · Ingress TLS 적용 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.7.1-01",
  "name": "Ingress TLS 적용 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Ingress",
    "required_data": [
      "cluster_ingresses"
    ],
    "condition": {
      "operator": "field_non_empty",
      "field": "spec.tls"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.7.1",
        "match_strength": "direct"
      },
      {
        "framework": "개인정보보호법",
        "item": "안전성 확보조치 - 전송 시 암호화",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "외부 송수신 시 평문 전송",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "미설정 Ingress가 외부 LB(CloudFront 등)에서 TLS 종료 후 평문 전달 구조인가",
      "그렇다면 클러스터 내 통신 보호 별도 통제 필요(mTLS 등)",
      "진짜 HTTP 평문이라면 즉시 시정"
    ],
    "manual_check_areas": [
      "저장 데이터 암호화 적용"
    ],
    "automation_coverage": {
      "percentage": 20,
      "covered": "Ingress 레벨 TLS",
      "not_covered": "Secret etcd 암호화, ConfigMap 평문, KMS 키 관리"
    },
    "alternative_controls": [
      "CloudFront/외부 LB TLS",
      "외부 인증서 관리"
    ],
    "k8s_only_check": true,
    "deferred": false,
    "deferred_reason": "AWS API 미접근으로 EKS describe/KMS/ALB 점검 불가"
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_ingresses`
  - 사람 검토 영역: 저장 데이터 암호화 적용

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-01 · Secret etcd 암호화 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-01",
  "name": "Secret etcd 암호화 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "manual_evidence_spec": {
    "title": "EKS 클러스터 Secret 암호화 설정 캡처",
    "description": "etcd에 저장되는 Kubernetes Secret이 KMS로 envelope 암호화되어 있음을 증명",
    "acceptable_formats": [
      "png",
      "jpg",
      "pdf",
      "json",
      "txt"
    ],
    "max_age_days": 365,
    "recommended_evidence_sources": [
      "AWS Console → EKS → 대상 클러스터 → Overview 탭 → 'Secrets encryption' 섹션 캡처",
      "CLI 출력 캡처/파일: `aws eks describe-cluster --name <CLUSTER명> --query 'cluster.encryptionConfig'`"
    ],
    "required_content": [
      {
        "field": "encryption_resources",
        "description": "암호화 대상에 'secrets' 포함 여부",
        "expected_pattern": "['secrets']"
      },
      {
        "field": "kms_key_arn",
        "description": "사용 중인 KMS 키 ARN",
        "expected_pattern": "^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$"
      },
      {
        "field": "cluster_name",
        "description": "EKS 클러스터명 (룰 평가 대상 클러스터와 일치 확인)"
      }
    ],
    "vlm_extraction_prompt": "이 캡처에서 EKS 클러스터의 Secret 암호화 설정 정보를 추출하라. 추출할 항목: (1) 암호화 대상 리소스 목록 (resources 또는 'Encrypted resources'에 'secrets'가 있는지), (2) KMS 키 ARN, (3) 클러스터 이름. JSON으로 응답."
  },
  "compliance_indicators": [
    {
      "field": "evidence.encryption_resources",
      "op": "contains",
      "value": "secrets",
      "description": "secrets 리소스가 암호화 대상에 포함"
    },
    {
      "field": "evidence.kms_key_arn",
      "op": "matches_regex",
      "value": "^arn:aws:kms:",
      "description": "유효한 KMS 키 ARN 존재"
    }
  ],
  "judgment_logic": {
    "type": "manual_evidence_match",
    "method": "vlm_extract_then_structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'Secret etcd 암호화 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - EKS 클러스터 암호화/KMS 설정값. ⚠️ cluster_* 스냅샷 테이블이 아니라 클러스터 메타·제출 증적에서 확인
  - 판정 기준: `evidence.encryption_resources contains secrets`; `evidence.kms_key_arn matches_regex ^arn:aws:kms:`

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-02 · ConfigMap 평문 비밀값 점검
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-02",
  "name": "ConfigMap 평문 비밀값 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "secret_patterns": [
    {
      "name": "password",
      "regex": "(?i)(password|passwd|pwd)\\s*[:=]\\s*[\"']?[\\w@!#$%^&*-]{6,}"
    },
    {
      "name": "aws_access_key",
      "regex": "AKIA[0-9A-Z]{16}"
    },
    {
      "name": "private_key",
      "regex": "-----BEGIN [A-Z ]*PRIVATE KEY-----"
    },
    {
      "name": "secret_token",
      "regex": "(?i)(secret|token|api[_-]?key)\\s*[:=]\\s*[\"']?[\\w\\-\\.]{16,}"
    },
    {
      "name": "jwt",
      "regex": "eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]+"
    }
  ],
  "compliance_indicators": [
    {
      "field": "configmap_has_secrets",
      "op": "==",
      "value": false,
      "description": "Pod가 참조하는 ConfigMap에 평문 비밀값 없음"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'ConfigMap 평문 비밀값 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_configmaps` (name, namespace)
  - 판정 기준: `configmap_has_secrets == False`

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-03 · 전송구간 TLS 적용 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-03",
  "name": "전송구간 TLS 적용 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "k8s_native_check": {
    "compliance_indicators": [
      {
        "field": "all_external_ingresses_have_tls",
        "op": "==",
        "value": true,
        "source": "k8s",
        "description": "외부 노출 Ingress 모두 .spec.tls 설정 존재"
      }
    ]
  },
  "manual_evidence_spec": {
    "title": "ALB Listener SSL 정책 캡처",
    "description": "외부 ALB의 HTTPS Listener가 TLS 1.2 이상의 승인된 SSL 정책을 사용함을 증명",
    "acceptable_formats": [
      "png",
      "jpg",
      "pdf",
      "txt",
      "json"
    ],
    "max_age_days": 180,
    "recommended_evidence_sources": [
      "AWS Console → EC2 → Load Balancers → 대상 ALB 선택 → Listeners 탭 → HTTPS:443 Listener의 'Security policy' 표시 캡처",
      "CLI 출력 캡처: `aws elbv2 describe-listeners --load-balancer-arn <ARN>`",
      "외부 검증: `nmap --script ssl-enum-ciphers -p 443 <도메인>` 출력 캡처"
    ],
    "approved_alb_ssl_policies": [
      "ELBSecurityPolicy-TLS13-1-2-2021-06",
      "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
      "ELBSecurityPolicy-FS-1-2-Res-2020-10"
    ],
    "tls_min_version": "TLSv1.2",
    "required_content": [
      {
        "field": "alb_arn_or_name",
        "description": "대상 ALB의 ARN 또는 이름 (Ingress와 매칭 확인용)"
      },
      {
        "field": "listener_protocol",
        "description": "Listener 프로토콜",
        "expected_pattern": "^HTTPS$"
      },
      {
        "field": "ssl_policy",
        "description": "사용 중인 SSL 정책명"
      }
    ],
    "vlm_extraction_prompt": "이 캡처에서 ALB(Application Load Balancer)의 HTTPS Listener 정보를 추출하라. 추출할 항목: (1) ALB 이름/ARN, (2) Listener 프로토콜(HTTP/HTTPS), (3) Security policy 또는 SSL policy 값. JSON으로 응답."
  },
  "compliance_indicators": [
    {
      "field": "all_external_ingresses_have_tls",
      "op": "==",
      "value": true,
      "source": "k8s",
      "description": "Ingress .spec.tls 설정 존재"
    },
    {
      "field": "evidence.listener_protocol",
      "op": "==",
      "value": "HTTPS",
      "source": "manual",
      "description": "ALB Listener HTTPS 사용"
    },
    {
      "field": "evidence.ssl_policy",
      "op": "in_approved_list",
      "value": "approved_alb_ssl_policies",
      "source": "manual",
      "description": "승인된 SSL 정책(TLS 1.2+) 사용"
    }
  ],
  "judgment_logic": {
    "type": "hybrid_match",
    "method": "k8s_structured_match + vlm_extract_then_structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '전송구간 TLS 적용 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `all_external_ingresses_have_tls == True`; `evidence.listener_protocol == HTTPS`; `evidence.ssl_policy in_approved_list approved_alb_ssl_policies`

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-04 · KMS 키 로테이션 및 상태 점검
*⚙️ 클라우드 실측(K8s, DB/증적)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-04",
  "name": "KMS 키 로테이션 및 상태 점검",
  "judgment_source": "k8s_api",
  "extraction_method": "rag",
  "manual_evidence_spec": {
    "title": "KMS Customer Managed Key 로테이션·상태 캡처",
    "description": "EKS Secret 암호화에 사용하는 KMS 키의 활성 상태, 자동 로테이션 활성, 승인 알고리즘 사용을 증명",
    "acceptable_formats": [
      "png",
      "jpg",
      "pdf",
      "json",
      "txt"
    ],
    "max_age_days": 90,
    "recommended_evidence_sources": [
      "AWS Console → Key Management Service → Customer managed keys → 대상 키 클릭 → 'General configuration' 및 'Key rotation' 탭 캡처",
      "CLI 출력 캡처/파일: `aws kms describe-key --key-id <KEY_ID 또는 ARN>`",
      "CLI 출력 캡처/파일: `aws kms get-key-rotation-status --key-id <KEY_ID 또는 ARN>`"
    ],
    "approved_key_specs": [
      "SYMMETRIC_DEFAULT",
      "RSA_2048",
      "RSA_3072",
      "RSA_4096"
    ],
    "required_content": [
      {
        "field": "key_arn",
        "description": "KMS 키 ARN"
      },
      {
        "field": "key_state",
        "description": "키 상태 (Enabled/Disabled/PendingDeletion 등)"
      },
      {
        "field": "key_enabled",
        "description": "키 사용 가능 여부 (Boolean)"
      },
      {
        "field": "key_spec",
        "description": "키 스펙 (알고리즘)"
      },
      {
        "field": "key_rotation_enabled",
        "description": "자동 키 로테이션 활성 여부 (Boolean)"
      }
    ],
    "vlm_extraction_prompt": "이 캡처에서 AWS KMS 키의 정보를 추출하라. 추출할 항목: (1) Key ARN, (2) Key state (Enabled 또는 다른 상태), (3) Enabled 값(true/false), (4) Key spec(SYMMETRIC_DEFAULT, RSA_2048 등), (5) Key rotation enabled 또는 'Automatic key rotation' 활성 여부. JSON으로 응답."
  },
  "compliance_indicators": [
    {
      "field": "evidence.key_state",
      "op": "==",
      "value": "Enabled",
      "description": "KMS 키 활성 상태"
    },
    {
      "field": "evidence.key_enabled",
      "op": "==",
      "value": true,
      "description": "KMS 키 사용 가능"
    },
    {
      "field": "evidence.key_rotation_enabled",
      "op": "==",
      "value": true,
      "description": "자동 키 로테이션 활성 (연 1회)"
    },
    {
      "field": "evidence.key_spec",
      "op": "in_approved_list",
      "value": "approved_key_specs",
      "description": "KISA 안내서 기준 알고리즘 사용 (AES-256 또는 RSA-2048 이상)"
    }
  ],
  "judgment_logic": {
    "type": "manual_evidence_match",
    "method": "vlm_extract_then_structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'KMS 키 로테이션 및 상태 점검' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_ingresses` (ingress_class, rules JSONB, tls JSONB)
  - 판정 기준: `evidence.key_state == Enabled`; `evidence.key_enabled == True`; `evidence.key_rotation_enabled == True`; `evidence.key_spec in_approved_list approved_key_specs`

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-GL01 · 암호정책 수립
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-GL01",
  "name": "암호정책 수립",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 등이 포함된 암호정책을 수립한다."
  ],
  "compliance_indicators": [
    {
      "description": "암호화 대상·강도·사용 정책을 포함한 암호정책을 수립하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.7.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'암호정책 수립'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 등이 포함된 암호정책을 수립한다.」

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-GL02 · 저장·전송·전달 시 암호화
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-GL02",
  "name": "저장·전송·전달 시 암호화",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "암호정책에 따라 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 수행한다."
  ],
  "compliance_indicators": [
    {
      "description": "개인정보·주요정보의 저장·전송·전달 시 암호화를 수행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.7.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'저장·전송·전달 시 암호화'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「암호정책에 따라 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 수행한다.」

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

## R-2.7.1-GL03 · 암호키 관리 절차
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.7.1-GL03",
  "name": "암호키 관리 절차",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "암호키의 생성·이용·보관·폐기·변경(로테이션) 등 키 관리 절차를 수립·이행한다."
  ],
  "compliance_indicators": [
    {
      "description": "암호키 생성·보관·폐기·변경 등 키 관리 절차를 수립·이행하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.7.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'암호키 관리 절차'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「암호키의 생성·이용·보관·폐기·변경(로테이션) 등 키 관리 절차를 수립·이행한다.」

**④ 당위성**
ISMS-P **2.7.1 암호정책 적용** 인증기준: "개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 개인정보 보호법 제24조의2, 개인정보 보호법 제29조, 개인정보의 안전성 확보조치 기준 제7조)

---

# 2.8.3 시험과 운영 환경 분리

## F-2.8.3-01 · 환경 라벨 적용 현황
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.8.3-01",
  "name": "환경 라벨 적용 현황",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "additional_evidence",
  "manual_meta": {
    "target_resource": "Pod",
    "required_data": [
      "cluster_pods.labels"
    ],
    "condition": {
      "operator": "label_value_in",
      "field": "labels.env",
      "values": [
        "prod",
        "stg",
        "dev",
        "test"
      ]
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.8.3",
        "match_strength": "indirect"
      }
    ],
    "kisa_defect_case_refs": [],
    "additional_review_items": [
      "회사가 env 라벨로 환경 구분 정책인가",
      "별도 클러스터/VPC로 환경 분리되어 있는가",
      "namespace 네이밍 컨벤션으로 식별되는가"
    ],
    "manual_check_areas": [
      "클러스터/VPC 분리 설계"
    ],
    "automation_coverage": {
      "percentage": 0,
      "covered": "K8s 라벨 컨벤션 채택 시",
      "not_covered": "클러스터/VPC 분리 점검"
    },
    "alternative_controls": [
      "별도 클러스터",
      "별도 VPC",
      "namespace 네이밍 컨벤션"
    ],
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.labels`
  - 사람 검토 영역: 클러스터/VPC 분리 설계

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## F-2.8.3-02 · 환경 혼재 namespace 발견
*🧑‍💻 클라우드 수동 점검(F-룰)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "F-2.8.3-02",
  "name": "환경 혼재 namespace 발견",
  "judgment_source": "k8s_api",
  "extraction_method": "manual",
  "verdict_type": "potential_finding",
  "manual_meta": {
    "target_resource": "Pod (cluster-wide)",
    "required_data": [
      "cluster_pods.labels",
      "cluster_namespaces"
    ],
    "condition": {
      "operator": "namespace_env_homogeneous"
    },
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.8.3",
        "match_strength": "direct"
      }
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "동일 시스템에서 운영/개발 병행",
        "match": "direct"
      }
    ],
    "additional_review_items": [
      "회사 환경 분리 정책이 namespace 단위인가 cluster 단위인가",
      "namespace 분리 정책이면 결함 가능",
      "cluster 분리 정책이면 namespace 내 혼재는 무관"
    ],
    "manual_check_areas": [],
    "automation_coverage": {
      "percentage": 100,
      "covered": "env 라벨 부여 시 namespace 내 혼재 점검",
      "not_covered": "라벨 미부여 시 점검 불가"
    },
    "k8s_only_check": true,
    "deferred": false
  }
}
```

**② 쉽게 설명**
자동 판정이 어려운 부분이라, 클러스터 스냅샷을 사람이 검토하는 **보조 점검(F-룰)**. 준수/검토필요로 표시.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블** + 사람 검토.
  - 집계 대상 테이블: `cluster_pods.labels`, `cluster_namespaces`

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.8.3-01 · 워크로드 env 라벨 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.8.3-01",
  "name": "워크로드 env 라벨 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "workload.metadata.labels.env",
      "op": "in",
      "value": [
        "production",
        "staging",
        "development",
        "test"
      ],
      "description": "워크로드에 유효한 환경 구분(env) 라벨 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** '워크로드 env 라벨 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_pods.labels` (JSONB) — 해당 키 조회 (예: `labels ->> 'data-classification'`)
  - 판정 기준: `workload.metadata.labels.env in ['production', 'staging', 'development', 'test']`

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.8.3-02 · namespace 내 prod/dev 워크로드 혼재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.8.3-02",
  "name": "namespace 내 prod/dev 워크로드 혼재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "conflicting_env_pairs": [
    [
      "production",
      "development"
    ],
    [
      "production",
      "test"
    ],
    [
      "production",
      "staging"
    ]
  ],
  "compliance_indicators": [
    {
      "field": "namespace_has_mixed_envs",
      "op": "==",
      "value": false,
      "description": "동일 namespace 내 운영(production)과 개발/시험 워크로드 미혼재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'namespace 내 prod/dev 워크로드 혼재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_workloads` (kind, selector, template_labels JSONB, containers JSONB)
  - 판정 기준: `namespace_has_mixed_envs == False`

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.8.3-03 · prod Secret이 dev에서 참조
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.8.3-03",
  "name": "prod Secret이 dev에서 참조",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "prod_secret_used_by_dev",
      "op": "==",
      "value": false,
      "description": "운영(production) 라벨 Secret이 개발/시험 워크로드에서 참조되지 않음"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'prod Secret이 dev에서 참조' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_secrets` (name, namespace, type)
  - 판정 기준: `prod_secret_used_by_dev == False`

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.8.3-GL01 · 개발·시험과 운영 환경 분리 원칙
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.8.3-GL01",
  "name": "개발·시험과 운영 환경 분리 원칙",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "개발 및 시험 시스템을 운영시스템과 원칙적으로 분리한다."
  ],
  "compliance_indicators": [
    {
      "description": "개발·시험 시스템을 운영시스템과 원칙적으로 분리하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.8.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'개발·시험과 운영 환경 분리 원칙'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「개발 및 시험 시스템을 운영시스템과 원칙적으로 분리한다.」

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

## R-2.8.3-GL02 · 분리 곤란 시 보완통제
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.8.3-GL02",
  "name": "분리 곤란 시 보완통제",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "불가피하게 개발과 운영 환경의 분리가 어려운 경우 상호검토, 상급자 모니터링, 변경 승인, 책임추적성 확보 등의 보안대책을 마련한다."
  ],
  "compliance_indicators": [
    {
      "description": "환경 분리가 어려운 경우 상호검토·모니터링·변경승인·책임추적성 등 보완통제를 마련하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.8.3",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'분리 곤란 시 보완통제'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「불가피하게 개발과 운영 환경의 분리가 어려운 경우 상호검토, 상급자 모니터링, 변경 승인, 책임추적성 확보 등의 보안대책을 마련한다.」

**④ 당위성**
ISMS-P **2.8.3 시험과 운영 환경 분리** 인증기준: "개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다. (법적 근거: 정보통신망법 제47조, 개인정보 보호법 제29조)

---

# 2.9.1 변경관리

## R-2.9.1-01 · change-cause annotation 부재
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.9.1-01",
  "name": "change-cause annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "deployment.metadata.annotations.kubernetes.io/change-cause",
      "op": "!=",
      "value": null,
      "description": "Deployment에 change-cause annotation 존재 — 변경 사유 기록됨"
    },
    {
      "field": "latest_replicaset_has_change_cause",
      "op": "==",
      "value": true,
      "description": "최신 ReplicaSet에 change-cause annotation 전파됨"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'change-cause annotation 부재' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_workloads` (kind, selector, template_labels JSONB, containers JSONB)
  - 판정 기준: `latest_replicaset_has_change_cause == True`

**④ 당위성**
ISMS-P **2.9.1 변경관리** 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.9.1-02 · revisionHistoryLimit=0 (롤백 불가)
*⚙️ 클라우드 실측(K8s, DB 적재값)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.9.1-02",
  "name": "revisionHistoryLimit=0 (롤백 불가)",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "deployment.spec.revisionHistoryLimit",
      "op": ">",
      "value": 0,
      "description": "revisionHistoryLimit > 0 — 이전 ReplicaSet 보존으로 롤백 가능"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  }
}
```

**② 쉽게 설명**
클러스터 상태가 적재된 **DB 스냅샷 테이블의 값을 읽어** 'revisionHistoryLimit=0 (롤백 불가)' 기준 충족 여부를 자동 판정한다.

**③ 무엇을 / 어디를 확인하나**
**DB 스냅샷 테이블/컬럼**에서 읽음:
  - `cluster_workloads` (kind, selector, template_labels JSONB, containers JSONB)
  - 판정 기준: `deployment.spec.revisionHistoryLimit > 0`

**④ 당위성**
ISMS-P **2.9.1 변경관리** 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.9.1-GL01 · 변경 절차 및 이력 관리
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.9.1-GL01",
  "name": "변경 절차 및 이력 관리",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정보시스템 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리한다."
  ],
  "compliance_indicators": [
    {
      "description": "정보시스템 변경 절차를 수립하고 변경 이력을 관리하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.9.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'변경 절차 및 이력 관리'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정보시스템 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리한다.」

**④ 당위성**
ISMS-P **2.9.1 변경관리** 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---

## R-2.9.1-GL02 · 변경 전 영향 분석
*📄 지침·정책 점검(문장기반 RAG)*

**① 실제 룰 JSON**
```json
{
  "rule_id": "R-2.9.1-GL02",
  "name": "변경 전 영향 분석",
  "judgment_source": "text_extraction",
  "extraction_method": "rag",
  "keywords": [
    "정보시스템 관련 자산 변경을 수행하기 전에 성능 및 보안에 미치는 영향을 분석한다."
  ],
  "compliance_indicators": [
    {
      "description": "변경 전 시스템에 미치는 성능·보안 영향을 분석하도록 규정"
    }
  ],
  "source_reference": {
    "framework": "ISMS-P",
    "item": "2.9.1",
    "basis": "안내서 주요 확인사항/인증기준"
  },
  "judgment_logic": {
    "type": "semantic_match",
    "method": "llm_rag_entailment",
    "match_criteria": "sentence_semantic_equivalence",
    "verdict_states": [
      "충족",
      "미충족",
      "확인불가"
    ]
  }
}
```

**② 쉽게 설명**
회사 지침서·정책 문서에 **'변경 전 영향 분석'**이(가) 글로 규정돼 있는지 본다. 키워드 매칭이 아니라 문서 문장과 요구 문장의 **의미가 같은지**를 LLM이 판단(RAG 함의)해 충족·미충족·확인불가로 가른다.

**③ 무엇을 / 어디를 확인하나**
**지침서·내부 정책 문서**(DB 등록 지침 텍스트)에서 확인.
  - 점검 기준 문장: 「정보시스템 관련 자산 변경을 수행하기 전에 성능 및 보안에 미치는 영향을 분석한다.」

**④ 당위성**
ISMS-P **2.9.1 변경관리** 인증기준: "정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다.". 이 룰은 그 요구사항이 실제로 지켜지는지 점검해 통제 이행 근거를 만든다.

---
