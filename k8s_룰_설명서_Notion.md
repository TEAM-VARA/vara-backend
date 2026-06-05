# ISMS-P k8s 실측 룰 설명서 (judgment_source=k8s_api · 61룰)

각 룰은 세 부분으로 설명합니다 — **① 원본 JSON(파일 그대로)** · **② 무엇을 보는지 상세** · **③ 처음 보는 사람용 친절 설명**.

> 대상: 클러스터를 실제로 점검하는 R룰(k8s_api) 61개. GL 정책룰(text_extraction 67개)은 제외.
> 배지: ⚙️ 실측 · 📋 리포트(판정 없음) · ⬆️ 승격 · ⏸️ 보류(eBPF)

---

# 1.2.1 정보자산 식별

> 인증기준: 조직의 업무특성에 따라 정보자산 분류기준을 수립하여 관리체계 범위 내 모든 정보자산을 식별·분류하고, 중요도를 산정한 후 그 목록을 최신으로 관리하여야 한다.

## R-1.2.1-01 — namespace 자산 분류 라벨
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

네임스페이스(namespace) 메타데이터 라벨 3종을 본다 — `data-classification`(public/internal/confidential/pii/sensitive-pii 중 하나), `isms-p/owner`(책임자), `isms-p/criticality`(critical/high/medium/low). 세 라벨이 모두 유효해야 충족(all_compliance_required, min_pass 1.0).

**③ 친절 설명**

쿠버네티스에서 namespace는 앱을 담는 '구획'이에요. 이 룰은 각 구획에 '이 안의 데이터는 어떤 등급이고, 담당자는 누구고, 얼마나 중요한가'라는 꼬리표(라벨)가 붙어 있는지 봅니다. 자산대장에 자산을 빠짐없이 등록했는지 확인하는 것과 같아요.

---

## R-1.2.1-02 — K8s 클러스터 자산 인벤토리
*📋 리포트(판정 없음·분모 제외)*

**① 원본 JSON**

```json
{
  "rule_id": "R-1.2.1-02",
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
    "offcluster_satisfaction_conditions": [
      "외부 자산관리대장/CMDB에 K8s 자산 + 온프레미스·외부위탁 자산이 통합 등재되고 분류·중요도가 산정돼 최신 관리됨"
    ],
    "k8s_only_check": true,
    "deferred": false
  },
  "reclassified_from": "F-1.2.1-01",
  "output_type": "report",
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-1.2.1-01",
    "additional_review_items": [
      "이 K8s 자산 목록이 회사 자산관리대장에 포함되어 있는가",
      "K8s 외 자산(온프레미스, 외부 위탁 등)은 별도 식별되어 있는가"
    ],
    "manual_check_areas": [
      "외부 위탁 자산 식별 절차",
      "자산관리시스템(CMDB)"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": 4,
        "description": "외부 위탁 IT 서비스 자산 식별 누락",
        "match": "partial"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "1.2.1",
        "match_strength": "supportive"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "외부 자산관리대장/CMDB에 K8s 자산 + 온프레미스·외부위탁 자산이 통합 등재되고 분류·중요도가 산정돼 최신 관리됨"
    ]
  }
}
```

**② 무엇을 보는지**

`inventory_report` operator. 판정(충족/미충족)이 아니라 클러스터의 namespace·pod·service·configmap 등을 모아 **자산 인벤토리 리포트**를 출력한다. (F-1.2.1-01에서 리포트로 재분류, 합격률 분모 제외)

**③ 친절 설명**

합격/불합격을 매기는 룰이 아니라, '지금 클러스터에 뭐가 떠 있는지' 목록을 뽑아 주는 리포트예요. 사람이 회사 자산관리대장과 대조할 때 쓰는 기초 자료입니다.

---

# 1.2.2 현황 및 흐름분석

> 인증기준: 관리체계 범위 내 정보서비스 및 개인정보 처리 현황을 분석하고, 업무절차와 흐름을 파악하여 정보서비스 흐름도, 개인정보 흐름도 등을 작성하여야 한다.

## R-1.2.2-01 — 외부 의존성 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

ExternalName 타입 Service의 라벨 2종 — `isms-p/external-dependency`(외부 의존성 분류), `isms-p/data-flow-id`(흐름도 매핑 ID) — 존재 여부를 본다. 둘 다 있어야 충족.

**③ 친절 설명**

ExternalName Service는 '클러스터 밖의 외부 시스템'을 가리키는 연결고리예요. 이 룰은 그런 외부 연결마다 '이건 어떤 외부 의존성이고 흐름도 어디에 해당하는지' 표시가 돼 있는지 봅니다. 외부로 나가는 통로를 빠짐없이 그림(흐름도)에 그렸는지 확인하는 거죠.

---

## R-1.2.2-02 — Ingress 흐름도 등록 annotation 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

Ingress의 annotation 2종 — `isms-p/flow-diagram-registered==true`, `isms-p/service-flow-id`(흐름도 ID) — 존재 여부를 본다.

**③ 친절 설명**

Ingress는 외부 사용자가 서비스로 들어오는 '정문'이에요. 이 룰은 각 정문이 정보서비스 흐름도에 등록돼 있다는 표시가 붙어 있는지 봅니다. 트래픽이 어디로 흐르는지 문서화했는지 확인하는 것입니다.

---

## R-1.2.2-03 — 클러스터 내부 통신 관계 인벤토리
*📋 리포트(판정 없음·분모 제외)*

**① 원본 JSON**

```json
{
  "rule_id": "R-1.2.2-03",
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
    "offcluster_satisfaction_conditions": [
      "도출된 통신 관계가 정보서비스 흐름도에 누락 없이 반영됨",
      "개인정보 처리 흐름이 개인정보 흐름도에 수집·보유·이용/제공·파기 단계로 표시됨"
    ],
    "k8s_only_check": true,
    "deferred": false
  },
  "reclassified_from": "F-1.2.2-01",
  "output_type": "report",
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-1.2.2-01",
    "additional_review_items": [
      "이 통신 관계가 회사 정보흐름도에 반영되어 있는가",
      "개인정보 처리 흐름이 별도 표시되어 있는가"
    ],
    "manual_check_areas": [
      "개인정보 처리 시스템 흐름도"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "1.2.2",
        "match_strength": "supportive"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "도출된 통신 관계가 정보서비스 흐름도에 누락 없이 반영됨",
      "개인정보 처리 흐름이 개인정보 흐름도에 수집·보유·이용/제공·파기 단계로 표시됨"
    ]
  }
}
```

**② 무엇을 보는지**

`traffic_graph_report` operator. 클러스터 내부 Pod 간 통신 관계를 모아 **통신 인벤토리 리포트**로 출력(판정 없음, 분모 제외).

**③ 친절 설명**

어떤 앱이 어떤 앱과 통신하는지 관계도를 뽑아 주는 리포트예요. 회사 정보흐름도와 비교해 빠진 게 없는지 볼 때 씁니다.

---

## R-1.2.2-04 — 외부 의존성 발견
*📋 리포트(판정 없음·분모 제외)*

**① 원본 JSON**

```json
{
  "rule_id": "R-1.2.2-04",
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
    "offcluster_satisfaction_conditions": [
      "발견된 외부 연계가 정보흐름도에 모두 등록돼 있고 외부 위탁 계약/외부 연계 시스템 목록과 일치함"
    ],
    "k8s_only_check": true,
    "deferred": false
  },
  "reclassified_from": "F-1.2.2-02",
  "output_type": "report",
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-1.2.2-02",
    "additional_review_items": [
      "발견된 외부 의존성이 모두 정보흐름도에 등록되어 있는가",
      "미등록 외부 연계 사유 확인",
      "외부 위탁 계약 현황 매칭"
    ],
    "manual_check_areas": [
      "외부 위탁 계약서",
      "외부 연계 시스템 목록"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "1.2.2",
        "match_strength": "supportive"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "발견된 외부 연계가 정보흐름도에 모두 등록돼 있고 외부 위탁 계약/외부 연계 시스템 목록과 일치함"
    ]
  }
}
```

**② 무엇을 보는지**

`external_dependency_report` operator. 클러스터가 의존하는 외부 연계를 찾아 **리포트**로 출력(판정 없음, 분모 제외).

**③ 친절 설명**

클러스터가 바깥의 어떤 시스템에 기대고 있는지(외부 의존성) 찾아서 목록으로 보여 주는 리포트예요. 외부 위탁 계약·연계 목록과 대조하는 자료입니다.

---

# 2.1.3 정보자산 관리

> 인증기준: 식별된 정보자산에 대하여 법적 요구사항 및 업무상 중요도를 고려하여 보안등급과 취급절차를 정하고, 이에 따라 취급하여야 한다.

## R-2.1.3-01 — 워크로드 owner annotation 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

```json
{
  "rule_id": "R-2.1.3-01",
  "name": "워크로드 owner annotation 부재",
  "judgment_source": "k8s_api",
  "extraction_method": "api",
  "compliance_indicators": [
    {
      "field": "pod.metadata.annotations.isms-p/owner",
      "op": "!=",
      "value": null,
      "description": "Pod에 자산 책임자(owner) annotation 존재"
    },
    {
      "field": "pod.metadata.annotations.isms-p/owner-team",
      "op": "!=",
      "value": null,
      "description": "Pod에 소유 팀(owner-team) annotation 존재"
    }
  ],
  "judgment_logic": {
    "type": "structured_match",
    "aggregation": "all_compliance_required",
    "min_pass_ratio": 1.0
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.1.3-01",
    "additional_review_items": [
      "회사가 K8s annotation으로 책임자를 관리하는 정책인가",
      "외부 자산관리시스템(CMDB)에서 책임자 매핑 여부",
      "책임자 미지정 자산의 사유 확인"
    ],
    "manual_check_areas": [
      "자산관리시스템(CMDB) 책임자 매핑"
    ],
    "alternative_controls": [
      "외부 CMDB",
      "ITSM 시스템"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.1.3",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "K8s owner 라벨이 없어도 외부 CMDB/ITSM에 워크로드의 책임자·소유팀이 매핑돼 있음"
    ]
  }
}
```

**② 무엇을 보는지**

Pod annotation 2종 — `pod.metadata.annotations.isms-p/owner`(책임자), `pod.metadata.annotations.isms-p/owner-team`(소유 팀) — 존재 여부를 본다. 둘 다 있어야 준수(all_compliance_required).

- **가져오는 곳**: 테이블 `cluster_pods` / 컬럼 `annotations`(JSONB)
- **JSON 필드 ↔ DB 매핑**: `pod.metadata.annotations.isms-p/owner` = `cluster_pods.annotations ->> 'isms-p/owner'`, `.../isms-p/owner-team` = `... ->> 'isms-p/owner-team'`
- **판정**: 두 키 모두 `!= null` ⇒ 준수 / 하나라도 없으면 미준수(누락 키를 violation으로 표기)
- **평가함수**: `evalWorkloadOwnerAnnotation`(pod_graph_eval_rules.go)이 Pod annotation을 직접 읽음. 기존 데이터 호환으로 `owner`/`contact`(책임자), `owner-team`(팀)을 fallback 키로 허용
- **manual_check_output(always)**: annotation이 없어도 외부 CMDB/ITSM에 책임자가 매핑돼 있을 수 있어, 그 외부 확인 항목을 함께 출력

> 변경 이력: 원래 인디케이터가 `workload.metadata.annotations.*`였는데 이 접두사는 DB 백킹 컬럼이 없어 항상 **확인불가(NO_DATA)**로 빠졌다. Pod 레벨(`pod.metadata.annotations.*`)로 교정해 `cluster_pods.annotations`에서 실제로 읽혀 준수/미준수 판정이 되도록 고침.

**③ 친절 설명**

Pod(실제 도는 컨테이너 묶음)마다 '책임자/담당팀이 누구인지' 꼬리표(annotation)가 붙어 있는지 봅니다. 그 값은 클러스터 스냅샷이 적재된 `cluster_pods` 테이블의 `annotations` 칸에서 읽어요. 책임자와 팀 두 꼬리표가 모두 있으면 준수, 하나라도 없으면 미준수입니다. (예전엔 workload(Deployment) 레벨을 가리켜 DB에 그 데이터가 없어서 '확인불가'로만 빠졌는데, Pod 레벨로 맞춰 실제 판정이 되게 고쳤어요.) 꼬리표가 없더라도 회사 자산관리시스템(CMDB)에 책임자가 적혀 있을 수 있어, 그건 사람이 따로 확인하라고 안내 항목을 같이 보여 줍니다.

---

## R-2.1.3-02 — security-class 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

워크로드 라벨 `security-class`가 critical/high/medium/low 중 하나로 설정돼 있는지 본다.

**③ 친절 설명**

앱마다 '보안 등급'이 매겨져 있는지 봅니다. 중요한 자산일수록 더 강하게 관리해야 하니, 등급표가 붙어 있는지 확인하는 거예요.

---

## R-2.1.3-03 — 자산 변경 활동 감지
*📋 리포트(판정 없음·분모 제외)*

**① 원본 JSON**

```json
{
  "rule_id": "R-2.1.3-03",
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
    "offcluster_satisfaction_conditions": [
      "감지된 변경이 변경관리(ITSM) 신청·승인 결재를 거쳤고 자산관리대장에 반영됨"
    ],
    "k8s_only_check": true,
    "deferred": false
  },
  "reclassified_from": "F-2.1.3-02",
  "output_type": "report",
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.1.3-02",
    "additional_review_items": [
      "이 변경 사항이 회사 자산관리 절차를 거쳤는가",
      "자산관리대장에 반영되었는가",
      "변경 신청/승인 결재 기록과 매칭"
    ],
    "manual_check_areas": [
      "변경관리 시스템(ITSM)",
      "자산관리대장"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.1.3",
        "match_strength": "supportive"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "감지된 변경이 변경관리(ITSM) 신청·승인 결재를 거쳤고 자산관리대장에 반영됨"
    ]
  }
}
```

**② 무엇을 보는지**

`change_activity_report` operator. 자산의 변경 활동(생성/수정 등)을 감지해 **리포트**로 출력(판정 없음, 분모 제외).

**③ 친절 설명**

클러스터에서 최근 무엇이 바뀌었는지(자산 변경 활동) 모아 보여 주는 리포트예요. 변경관리 절차·결재 기록과 대조하는 자료입니다.

---

# 2.5.1 사용자 계정 관리

> 인증기준: 정보시스템과 개인정보 및 중요정보에 대한 사용자 계정 발급 시 업무상 필요한 최소한의 접근 권한을 부여하고, 불필요한 계정은 삭제하여야 한다.

## R-2.5.1-01 — default ServiceAccount 사용
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.5.1-01",
    "additional_review_items": [
      "해당 Pod가 인증범위 내 자산인가",
      "default SA 사용에 대한 회사 정책상 예외 허용 사례인가",
      "시스템 namespace는 예외 처리"
    ],
    "manual_check_areas": [
      "공용 계정 사용 예외 승인 기록"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "공용 계정 사용",
        "match": "direct"
      }
    ],
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
    "offcluster_satisfaction_conditions": [
      "시스템 namespace(kube-system·kube-public·kube-node-lease) 예외 대상",
      "공용/default SA 사용에 책임자 예외 승인 기록 있음(인증범위 내 일반 워크로드면 전용 SA 필요)"
    ],
    "exception_namespaces": [
      "kube-system",
      "kube-public",
      "kube-node-lease"
    ]
  }
}
```

**② 무엇을 보는지**

Pod의 `spec.serviceAccountName`이 `default`가 아닌지 본다(전용 SA 사용 여부). manual_check_output(fail): 미충족 시 공용계정 예외 승인 기록 확인 + 시스템 namespace(kube-system 등) 예외 안내를 함께 출력.

**③ 친절 설명**

쿠버네티스에서 앱은 'ServiceAccount(서비스 계정)'으로 클러스터에 접근해요. 아무 설정 안 하면 모두가 공용인 `default` 계정을 쓰는데, 그러면 누가 무엇을 했는지 추적이 안 됩니다. 이 룰은 앱마다 전용 계정을 쓰는지 봅니다(공용계정 금지). 미충족이면 사람이 예외 승인 기록을 확인하도록 안내합니다.

---

## R-2.5.1-02 — ServiceAccount owner 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

ServiceAccount 라벨 2종 — `isms-p/owner`(소유자), `isms-p/purpose`(용도) — 존재 여부를 본다.

**③ 친절 설명**

서비스 계정마다 '누구 것이고 어디에 쓰는지' 표시가 붙어 있는지 봅니다. 계정 대장을 제대로 적었는지 확인하는 거예요.

---

## R-2.5.1-03 — 팀 간 ServiceAccount 공유
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`sa_shared_across_teams==False` — 동일 ServiceAccount를 서로 다른 팀의 워크로드가 공유하지 않는지 본다.

**③ 친절 설명**

한 서비스 계정을 여러 팀이 돌려쓰면 사고가 나도 책임 소재가 흐려져요. 이 룰은 계정이 팀을 넘나들며 공유되고 있지 않은지 봅니다.

---

## R-2.5.1-04 — 미사용(orphan) ServiceAccount 발견
*⬆️ R로 승격(자동 점검)*

**① 원본 JSON**

```json
{
  "rule_id": "R-2.5.1-04",
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
    "offcluster_satisfaction_conditions": [
      "해당 SA가 예정 사용분으로 문서화돼 있거나 계정 정기 점검 기록상 인지·관리됨"
    ],
    "k8s_only_check": true,
    "deferred": false
  },
  "promoted_from": "F-2.5.1-02",
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.5.1-02",
    "additional_review_items": [
      "이 SA들이 계획된 향후 사용을 위한 것인가",
      "정기 점검 미실시로 잔존한 계정인가",
      "회사의 계정 정기 점검 주기/기록 확인"
    ],
    "manual_check_areas": [
      "최근 점검 기록"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "불필요 계정 정기 점검/삭제 미흡",
        "match": "partial"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.1",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "해당 SA가 예정 사용분으로 문서화돼 있거나 계정 정기 점검 기록상 인지·관리됨"
    ]
  }
}
```

**② 무엇을 보는지**

`orphan_serviceaccount` operator로 **미사용(orphan) SA**를 찾는다 = 존재하는 SA에서 RoleBinding/ClusterRoleBinding에 묶이지 않은 것(SA − bindings). F-2.5.1-02에서 R로 승격(자동 계산 가능). 분모 포함.

**③ 친절 설명**

아무 권한에도 연결되지 않은 채 남아 있는 '버려진 계정'을 찾아냅니다. 안 쓰는 계정은 정기적으로 정리해야 침해 통로가 안 되거든요. 원래 수동 점검이었지만 계산으로 자동 탐지가 가능해 정식 점검 룰로 승격했어요.

---

# 2.5.2 사용자 식별

> 인증기준: 정보시스템과 개인정보 및 중요정보에 대한 접근은 사용자별로 고유하게 식별·인증할 수 있어야 하며, 동일한 사용자 계정을 공유하여 사용하지 않도록 하여야 한다.

## R-2.5.2-01 — 추측 가능한 SA 이름
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.5.2-01",
    "additional_review_items": [
      "해당 SA가 인증범위 내 자산인가",
      "명명 자체보다 권한 범위 점검(F-2.5.5와 결합)",
      "회사 명명 규칙 문서와 비교"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "admin, guest, test 등 추측 가능한 ID 운영",
        "match": "direct"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.2",
        "match_strength": "direct"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "명명 규칙 문서상 허용된 명칭이거나, SA 권한이 최소화돼 위험이 통제됨"
    ]
  }
}
```

**② 무엇을 보는지**

`sa_name_is_guessable==False` — ServiceAccount 이름이 admin/guest/test 같이 추측 가능한 패턴(guessable_name_patterns)인지 본다. manual_check_output(fail): 명명규칙 문서 대조 안내.

**③ 친절 설명**

계정 이름이 admin, test처럼 누구나 짐작할 수 있으면 공격 대상이 되기 쉬워요. 이 룰은 계정 이름이 그런 뻔한 이름인지 봅니다.

---

## R-2.5.2-02 — 일반 명명 패턴
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.5.2-02",
    "additional_review_items": [
      "용도가 의미적으로 식별 가능한가",
      "운영 표준 명명 규칙과 일치하는가"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.5.2",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "운영 표준 명명 규칙 문서상 용도가 의미적으로 식별 가능하게 매핑·관리됨"
    ]
  }
}
```

**② 무엇을 보는지**

`sa_name_is_generic==False` — 이름이 너무 일반적(generic_naming_patterns)이라 용도를 식별하기 어려운지 본다. manual_check_output(fail) 동반.

**③ 친절 설명**

계정 이름이 너무 두루뭉술하면(예: sa1, default-sa) 어디에 쓰는지 알 수 없어 관리가 안 돼요. 이 룰은 이름만 보고도 용도를 알 수 있게 지어졌는지 봅니다.

---

# 2.5.4 비밀번호 관리

> 인증기준: 법적 요구사항, 외부 위협요인 등을 고려하여 정보시스템 사용자 및 고객, 회원 등 정보주체(이용자)가 사용하는 비밀번호 관리절차를 수립·이행하여야 한다.

## R-2.5.4-03 — OS 패스워드 정책 설정값 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

수집된 OS 설정값을 본다 — `PASS_MAX_DAYS<=180`, `PASS_MIN_LEN>=8`, pam_pwquality `minlen>=10`, `dcredit/ucredit/ocredit<=-1`(숫자·대문자·특수문자 강제). 모두 충족해야 통과.

**③ 친절 설명**

리눅스 서버의 비밀번호 규칙이 충분히 강한지 봅니다 — 최대 180일마다 변경, 최소 길이, 숫자·대문자·특수문자 의무화 등. 회사 비밀번호 정책이 OS에 실제로 설정돼 있는지 확인하는 거예요.

---

## R-2.5.4-04 — AD 패스워드 정책 설정값 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

Active Directory 정책값을 본다 — 최소 길이>=8, 최대 사용기간<=180, 복잡성 Enabled, 이력>=4, 잠금 임계<=5.

**③ 친절 설명**

윈도우 도메인(AD)의 비밀번호 규칙이 기준을 만족하는지 봅니다. 길이·변경주기·복잡성·재사용 금지·계정 잠금 같은 항목을 확인해요.

---

## R-2.5.4-05 — IAM 패스워드 정책 설정값 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

AWS IAM 패스워드 정책을 본다 — 최소 길이>=10, 대/소문자·숫자·특수문자 필수, 최대 사용기간<=180, 재사용 방지>=4.

**③ 친절 설명**

AWS 콘솔 로그인 비밀번호 규칙이 기준을 만족하는지 봅니다. 클라우드 계정도 비밀번호 정책을 강하게 걸어 둬야 하니까요.

---

## R-2.5.4-06 — DB 패스워드 정책 설정값 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

DB 계정 정책을 본다 — Oracle `PASSWORD_LIFE_TIME<=180`·`FAILED_LOGIN_ATTEMPTS<=5`·검증함수 활성, MySQL `validate_password.policy==STRONG`·`length>=8`.

**③ 친절 설명**

데이터베이스 계정의 비밀번호 규칙이 강한지 봅니다. DB는 핵심 데이터를 담으니 변경주기·잠금·복잡성 검증이 켜져 있어야 해요.

---

## R-2.5.4-07 — WAS 패스워드 정책 설정값 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

WAS(웹 애플리케이션 서버) 정책을 본다 — 검증 Provider Enabled, 잠금 임계<=5, 잠금 시간>=30, 최소 길이>=8.

**③ 친절 설명**

웹 애플리케이션 서버의 로그인 비밀번호 규칙이 기준을 만족하는지 봅니다.

---

## R-2.5.4-08 — 회원가입·비밀번호 변경 화면 강제화 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

회원가입·비밀번호 변경 화면의 동작을 의미 기반(semantic_match)으로 본다 — 짧은/약한 비밀번호 입력 시 가입을 거부하는지 등.

**③ 친절 설명**

사용자가 직접 비밀번호를 만드는 화면에서, 너무 약한 비밀번호를 막아 주는지 봅니다. 규칙이 문서에만 있고 실제 화면에선 안 막으면 소용없으니까요.

---

## R-2.5.4-09 — 비밀번호 변경주기 준수 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

변경주기 준수를 통계(aggregated_statistics)로 본다 — 마지막 변경 후 180일 미만, 모든 활성 계정에 변경일 존재, 주기 도래 시 강제변경 로그.

**③ 친절 설명**

사용자들이 실제로 비밀번호를 주기적으로 바꾸고 있는지 통계로 봅니다. 오래 안 바꾼 계정이 방치되지 않는지 확인해요.

---

## R-2.5.4-10 — 임시 비밀번호 강제 변경 코드 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

임시 비밀번호 강제 변경을 코드 패턴(code_pattern_match)으로 본다 — 강제 변경 이후에만 정상 세션을 발급하는 로직이 있는지.

**③ 친절 설명**

임시 비밀번호로 처음 로그인하면 반드시 새 비밀번호로 바꾸게 코드가 짜여 있는지 봅니다.

---

## R-2.5.4-11 — 임시 비밀번호 강제 변경 화면 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

임시 비밀번호 강제 변경을 화면(semantic_match)으로 본다 — 임시 비번 로그인 후 변경 화면으로 redirect되고, 변경 전엔 다른 페이지 접근 불가.

**③ 친절 설명**

임시 비밀번호로 들어오면 비밀번호 변경 화면으로 강제로 보내고, 바꾸기 전엔 아무것도 못 하게 하는지 봅니다.

---

## R-2.5.4-12 — 임시 비밀번호 미변경자 목록 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

임시 비밀번호 미변경자 목록을 통계로 본다 — 미변경자 0명, 최근 24시간 이내 발급 사례만, 미변경 시 자동 잠금.

**③ 친절 설명**

임시 비밀번호를 받고도 안 바꾼 사람이 남아 있는지 봅니다. 방치된 임시 계정은 위험하니까요.

---

## R-2.5.4-13 — DB 비밀번호 저장 형태 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

DB에 저장된 비밀번호 형태를 정규식(regex_match)으로 본다 — bcrypt/argon2/scrypt/PBKDF2 또는 SHA-256/512+salt 같은 안전한 해시인지.

**③ 친절 설명**

데이터베이스에 비밀번호가 평문이나 약한 방식이 아니라, 되돌릴 수 없는 안전한 해시로 저장돼 있는지 봅니다.

---

## R-2.5.4-14 — MFA 설정 정책 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

MFA(다단계 인증) 정책을 본다 — 외부 접속 시 OTP 화면 존재, 인증수단별 적용 대상 명시(관리자=하드웨어 토큰 등). 관리자 MFA 필수+전체 권고.

**③ 친절 설명**

비밀번호 외에 추가 인증(OTP 등)을 쓰는지 봅니다. 특히 관리자는 반드시 다단계 인증을 걸어야 해요.

---

## R-2.5.4-15 — 로그인 화면 인증수단 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

로그인 화면을 의미 기반으로 본다 — 실패 시 일반적 메시지(계정 존재 여부 노출 금지), 2단계 인증 단계 존재 등.

**③ 친절 설명**

로그인 화면이 안전하게 만들어졌는지 봅니다 — 예를 들어 '아이디가 틀렸는지/비번이 틀렸는지'를 알려 주지 않고, 2단계 인증을 제공하는지 등.

---

# 2.5.5 특수 계정 및 권한 관리

> 인증기준: 정보시스템 관리, 개인정보 및 중요정보 관리 등 특수 목적을 위하여 사용하는 계정 및 권한은 최소한으로 부여하고 별도로 식별하여 통제하여야 한다.

## R-2.5.5-01 — ServiceAccount 특수 권한 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.5.5-01",
    "manual_check_areas": [
      "권한 부여 결재 기록"
    ],
    "offcluster_satisfaction_conditions": [
      "최고권한(cluster-admin 등) 부여가 신청·승인 결재로 정당화되고 별도 식별·감사(책임추적성) 대상으로 관리됨"
    ]
  }
}
```

**② 무엇을 보는지**

ServiceAccount의 RBAC 권한을 본다 — `has_cluster_admin==False`(cluster-admin 바인딩 없음), `has_wildcard_permission==False`(verbs:*+resources:* 없음), `has_cluster_wide_secrets==False`(전체 Secret 접근 없음). manual_check_output(fail): 특수권한자 목록·결재 기록 확인 안내.

**③ 친절 설명**

서비스 계정이 '클러스터 최고 권한(cluster-admin)'이나 '뭐든 다 할 수 있는 와일드카드 권한'을 갖고 있지 않은지 봅니다. 권한은 꼭 필요한 만큼만(최소권한) 줘야 사고 시 피해가 작아요.

---

## R-2.5.5-02 — 위험 RBAC verb 조합 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.5.5-02",
    "manual_check_areas": [
      "RBAC 정책 문서 확인",
      "권한 부여 결재 기록"
    ],
    "offcluster_satisfaction_conditions": [
      "위험 권한이 결재 승인 + RBAC 정책 문서상 정당화되고 예외 사유(rbac-exception)·감사로 통제됨"
    ]
  }
}
```

**② 무엇을 보는지**

`has_dangerous_verb_combo==False` — 위험한 권한(verb) 조합(dangerous_verb_combinations, 예: secrets get+create+escalate, pods/exec, impersonate)을 보유했는지 본다. exception_check로 예외 허용.

**③ 친절 설명**

각각은 평범해 보여도 합쳐지면 권한 탈취로 이어지는 위험한 권한 조합(예: 비밀 읽기+권한 올리기, 컨테이너 안으로 들어가기)을 가졌는지 봅니다.

---

# 2.6.1 네트워크 접근

> 인증기준: 네트워크에 대한 비인가 접근을 통제하기 위하여 IP 관리, 단말 인증 등 관리절차를 수립·이행하고, 업무 목적 및 중요도에 따라 네트워크 분리(DMZ, 서버팜, DB존, 개발존 등)와 접근통제를 적용하여야 한다.

## R-2.6.1-01 — hostNetwork 사용 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

Pod의 `spec.hostNetwork`/`hostPID`/`hostIPC`가 모두 비활성(!=true)인지 본다. exception_check로 시스템 Pod 예외.

**③ 친절 설명**

컨테이너가 호스트(노드) 자신의 네트워크·프로세스·메모리 공간을 그대로 쓰면 격리가 깨져 매우 위험해요. 이 룰은 그런 '호스트 직접 사용'이 꺼져 있는지 봅니다.

---

## R-2.6.1-02 — NetworkPolicy 적용 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.6.1-01",
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
    "alternative_controls": [
      "VPC subnet 분리 + Security Group",
      "Istio AuthorizationPolicy",
      "Calico GlobalNetworkPolicy",
      "별도 클러스터 운영"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "서버팜과 사무망 미분리",
        "match": "partial"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.1",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "영역 분리가 VPC 서브넷+SG / 별도 클러스터 / Istio AuthorizationPolicy / Calico GlobalNetworkPolicy 등으로 적용됨"
    ]
  }
}
```

**② 무엇을 보는지**

NetworkPolicy를 본다 — `has_default_deny==True`(Ingress+Egress 기본 차단 정책 존재) + `has_matching_policy==True`(Pod에 매칭되는 허용 정책 존재). manual_check_output(always): K8s 외 VPC/SG/Istio/Calico 등 대체 분리통제 확인 안내(cluster-level 관측).

**③ 친절 설명**

쿠버네티스는 기본적으로 모든 Pod가 서로 통신 가능해요. NetworkPolicy로 '기본은 차단, 필요한 것만 허용'을 걸어야 안전합니다. 이 룰은 그 차단 정책이 깔려 있는지 봅니다. 단, VPC 서브넷/보안그룹 같은 K8s 밖 통제로 분리했을 수도 있어 그건 사람이 확인하도록 안내합니다.

---

## R-2.6.1-03 — CNI NetworkPolicy 강제 지원 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.6.1-02",
    "additional_review_items": [
      "미발견 시 K8s NetworkPolicy 무효화 가능성 - 외부 통제로 분리 확인",
      "발견 시 정책 강제 옵션 활성화 여부(도구는 옵션 미확인)"
    ],
    "manual_check_areas": [
      "CNI 설정 문서",
      "Network 강제 정책 운영 상태"
    ],
    "alternative_controls": [
      "AWS VPC CNI + Security Group",
      "Service Mesh",
      "외부 NetFW"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.1",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "AWS VPC CNI+SG, Service Mesh, 외부 방화벽 등으로 통신 통제가 강제됨(정책 강제 CNI 미발견이어도)"
    ]
  }
}
```

**② 무엇을 보는지**

`has_policy_capable_cni==True`(NetworkPolicy를 강제할 수 있는 CNI DaemonSet 존재) + `policy_enforcement_enabled==True`(aws-vpc-cni면 aws-node env에 ENABLE_NETWORK_POLICY=true)인지 본다. manual_check_output(always) 동반.

**③ 친절 설명**

NetworkPolicy를 만들어도 그걸 실제로 '강제'할 수 있는 네트워크 플러그인(CNI)이 깔려 있어야 효력이 있어요. 이 룰은 정책을 집행할 엔진이 켜져 있는지 봅니다. 정책을 써 붙여도 단속반이 없으면 의미가 없는 것과 같죠.

---

## R-2.6.1-04 — cross-namespace 통신 통제 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.6.1-03",
    "additional_review_items": [
      "영역별 분리가 cluster 또는 VPC 분리로 이뤄지면 K8s 통제 불필요",
      "단일 클러스터 내 영역 분리라면 K8s 통제 적용 권장"
    ],
    "manual_check_areas": [
      "네트워크 분리 설계 문서",
      "VPC 분리 정책"
    ],
    "alternative_controls": [
      "VPC 라우팅",
      "Service Mesh",
      "별도 클러스터"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.1",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "운영/개발 영역이 별도 VPC(서브넷+SG)/별도 클러스터로 분리",
      "Service Mesh AuthorizationPolicy/mTLS로 ns 간 통신 차단"
    ]
  }
}
```

**② 무엇을 보는지**

`cross_ns_egress_controlled==True` — Pod에 매칭되는 egress NetworkPolicy로 namespace를 넘는(cross-namespace) 통신이 통제되는지 본다. manual_check_output(always, ns쌍 cluster-level 관측).

**③ 친절 설명**

한 구획(namespace)의 앱이 다른 구획으로 마음대로 통신하지 못하게 막혀 있는지 봅니다. 구획 간 칸막이가 제대로 쳐져 있는지 확인하는 거예요.

---

# 2.6.3 응용프로그램 접근

> 인증기준: 사용자별 업무 및 접근 정보의 중요도 등에 따라 응용프로그램 접근권한을 제한하고, 불필요한 정보 또는 중요정보 노출을 최소화할 수 있도록 기준을 수립하여 적용하여야 한다.

## R-2.6.3-01 — Ingress 인증 적용 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`all_ingresses_have_auth==True` — Pod에 연결된 모든 Ingress에 인증 설정(auth_annotations에 정의된 인증 annotation)이 적용됐는지 본다.

**③ 친절 설명**

외부에서 들어오는 입구(Ingress)마다 로그인/인증이 걸려 있는지 봅니다. 인증 없이 노출된 입구가 없는지 확인하는 거예요.

---

## R-2.6.3-02 — 내부 Service mTLS 강제 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`istio_injection_enabled==True`(namespace에 Istio sidecar 자동 주입) + `effective_mtls_mode==STRICT`(PeerAuthentication mTLS STRICT 적용)인지 본다.

**③ 친절 설명**

클러스터 내부 서비스끼리 주고받는 통신도 암호화(mTLS)되는지 봅니다. 내부망이라고 평문으로 흘리면 내부 침해 시 그대로 노출되니까요.

---

# 2.6.7 인터넷 접속 통제

> 인증기준: 업무용 단말기 등에서 인터넷에 접속할 경우 정보유출 등의 보안사고를 예방하기 위하여 인터넷 접속 통제 정책을 수립·이행하여야 한다.

## R-2.6.7-01 — egress NetworkPolicy 미적용
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.6.7-01",
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
    "alternative_controls": [
      "VPC NAT Gateway 화이트리스트",
      "프록시 서버(Squid 등)",
      "Cilium FQDN policy",
      "AWS Network Firewall"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "운영 서버에서 외부 인터넷 자유 접속",
        "match": "direct"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.7",
        "match_strength": "direct"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "VPC NAT Gateway 화이트리스트 / 프록시(Squid 등) / Cilium FQDN policy / AWS Network Firewall로 아웃바운드 통제됨"
    ]
  }
}
```

**② 무엇을 보는지**

`has_egress_policy==True`(Pod에 매칭되는 Egress NetworkPolicy 존재) + `egress_default_deny_exists==True`(namespace Egress 기본차단 존재)인지 본다. exception_check 예외. manual_check_output(always): NAT GW 화이트리스트/프록시/Cilium FQDN 등 대체통제 안내.

**③ 친절 설명**

앱이 외부 인터넷으로 '나가는' 트래픽이 통제되는지 봅니다. 운영 서버가 아무 데나 자유롭게 인터넷에 접속하면 악성코드 유출입 통로가 되거든요. K8s 밖에서 NAT 게이트웨이/프록시로 막았을 수도 있어 그건 사람이 확인하도록 안내합니다.

---

## R-2.6.7-02 — 실제 외부 도메인 접속 관찰 (eBPF)
*⏸️ 보류(eBPF 연동 후 활성)*

**① 원본 JSON**

```json
{
  "rule_id": "R-2.6.7-02",
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
    "offcluster_satisfaction_conditions": [
      "관찰된 외부 접속이 화이트리스트 범위 내이고 의심 도메인 없음(DNS 로그 분석 기록으로 확인)"
    ],
    "k8s_only_check": true,
    "deferred": true,
    "deferred_reason": "행위 관측(외부 도메인 트래픽). eBPF/DNS 로그 파이프라인 연동 후 활성화"
  },
  "deferred_from": "F-2.6.7-02",
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.6.7-02",
    "additional_review_items": [
      "화이트리스트와 실제 접속 패턴 일치 여부",
      "의심 도메인 접속이 있는가",
      "개인정보 처리 Pod의 외부 접속 패턴 검토"
    ],
    "manual_check_areas": [
      "외부 접속 화이트리스트",
      "DNS 로그 분석 기록"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.6.7",
        "match_strength": "supportive"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "관찰된 외부 접속이 화이트리스트 범위 내이고 의심 도메인 없음(DNS 로그 분석 기록으로 확인)"
    ]
  }
}
```

**② 무엇을 보는지**

`external_domain_traffic_report` operator. 실제 외부 도메인 접속을 eBPF로 관찰하려는 룰이나 **deferred=true(보류)** — eBPF/DNS 로그 파이프라인 연동 전이라 분모 제외. 연동되면 활성.

**③ 친절 설명**

앱이 실제로 어떤 외부 도메인에 접속하는지 '관찰'하려는 룰이에요. 다만 이걸 보려면 eBPF(커널 수준 관측) 데이터가 필요한데 아직 연동 전이라 '보류' 상태입니다. 데이터가 들어오면 켜집니다.

---

# 2.7.1 암호정책 적용

> 인증기준: 개인정보 및 주요정보의 보호를 위하여 법적 요구사항을 반영한 암호화 대상, 암호 강도, 암호 사용 정책을 수립하고 개인정보 및 주요정보의 저장·전송·전달 시 암호화를 적용하여야 한다.

## R-2.7.1-01 — Secret etcd 암호화 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

증적(evidence) 기반 — `encryption_resources`에 secrets가 포함되고 `kms_key_arn`이 유효한 ARN(^arn:aws:kms:)인지 본다. EKS Secret의 etcd 저장 시 KMS 암호화 적용 여부.

**③ 친절 설명**

쿠버네티스 비밀정보(Secret)가 저장소(etcd)에 암호화돼 보관되는지 봅니다. 비밀번호·토큰 같은 민감정보가 평문으로 디스크에 남으면 안 되니까요.

---

## R-2.7.1-02 — ConfigMap 평문 비밀값 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`configmap_has_secrets==False` — Pod가 참조하는 ConfigMap 안에 secret_patterns(비밀번호·키·토큰 정규식)에 걸리는 평문 비밀값이 없는지 본다.

**③ 친절 설명**

ConfigMap은 '설정값'을 담는 곳이라 암호화가 안 돼요. 그런데 여기에 비밀번호나 API 키를 평문으로 넣는 실수가 흔합니다. 이 룰은 설정 안에 비밀값이 새어 들어가 있지 않은지 봅니다.

---

## R-2.7.1-03 — 전송구간 TLS 적용 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.7.1-01",
    "additional_review_items": [
      "미설정 Ingress가 외부 LB(CloudFront 등)에서 TLS 종료 후 평문 전달 구조인가",
      "그렇다면 클러스터 내 통신 보호 별도 통제 필요(mTLS 등)",
      "진짜 HTTP 평문이라면 즉시 시정"
    ],
    "manual_check_areas": [
      "저장 데이터 암호화 적용"
    ],
    "alternative_controls": [
      "CloudFront/외부 LB TLS",
      "외부 인증서 관리"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "외부 송수신 시 평문 전송",
        "match": "direct"
      }
    ],
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
    "offcluster_satisfaction_conditions": [
      "외부 LB(CloudFront/ALB) TLS 종료 후 내부는 mTLS 보호 구조",
      "저장 데이터 암호화(Secret etcd·KMS)가 별도 적용됨"
    ]
  }
}
```

**② 무엇을 보는지**

혼합 판정(hybrid) — `all_external_ingresses_have_tls==True`(Ingress .spec.tls 존재) + 증적의 `listener_protocol==HTTPS`(ALB HTTPS) + `ssl_policy`가 승인 목록(TLS 1.2+)인지 본다. manual_check_output(fail) 동반.

**③ 친절 설명**

외부와 주고받는 통신이 HTTPS(TLS)로 암호화되는지 봅니다. 입구(Ingress)에 인증서가 설정됐는지와, 로드밸런서가 안전한 TLS 버전을 쓰는지를 함께 확인해요.

---

## R-2.7.1-04 — KMS 키 로테이션 및 상태 점검
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

증적 기반 — KMS 키의 `key_state==Enabled`·`key_enabled==True`·`key_rotation_enabled==True`(자동 로테이션)·`key_spec`이 승인 알고리즘(AES-256/RSA-2048+)인지 본다.

**③ 친절 설명**

암호화에 쓰는 KMS 열쇠(키)가 살아 있고, 정기적으로 자동 교체되며, 충분히 강한 알고리즘인지 봅니다. 열쇠 관리가 곧 암호화의 핵심이니까요.

---

# 2.8.3 시험과 운영 환경 분리

> 인증기준: 개발 및 시험 시스템은 운영시스템에 대한 비인가 접근 및 변경의 위험을 감소시키기 위하여 원칙적으로 분리하여야 한다.

## R-2.8.3-01 — 워크로드 env 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.8.3-01",
    "additional_review_items": [
      "회사가 env 라벨로 환경 구분 정책인가",
      "별도 클러스터/VPC로 환경 분리되어 있는가",
      "namespace 네이밍 컨벤션으로 식별되는가"
    ],
    "manual_check_areas": [
      "클러스터/VPC 분리 설계"
    ],
    "alternative_controls": [
      "별도 클러스터",
      "별도 VPC",
      "namespace 네이밍 컨벤션"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.8.3",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "env 라벨이 없어도 별도 클러스터/별도 VPC/namespace 네이밍 컨벤션으로 환경 식별·분리됨"
    ]
  }
}
```

**② 무엇을 보는지**

워크로드 라벨 `env`가 production/staging/development/test 중 하나인지 본다. manual_check_output(always): 라벨 없어도 별도 클러스터/VPC/네이밍으로 환경 분리됐는지 확인 안내.

**③ 친절 설명**

앱마다 '운영용/개발용/시험용' 같은 환경 꼬리표가 붙어 있는지 봅니다. 운영과 개발을 섞으면 사고가 나니 우선 구분 표시부터 돼 있어야 해요.

---

## R-2.8.3-02 — namespace 내 prod/dev 워크로드 혼재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.8.3-02",
    "additional_review_items": [
      "회사 환경 분리 정책이 namespace 단위인가 cluster 단위인가",
      "namespace 분리 정책이면 결함 가능",
      "cluster 분리 정책이면 namespace 내 혼재는 무관"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "동일 시스템에서 운영/개발 병행",
        "match": "direct"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.8.3",
        "match_strength": "direct"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "환경 분리 정책이 cluster/VPC 단위이고 그 수준에서 분리됨 → ns 내 혼재 무관(ns 단위 분리 정책이면 결함)"
    ]
  }
}
```

**② 무엇을 보는지**

`namespace_has_mixed_envs==False` — 같은 namespace 안에 운영(production)과 개발/시험 워크로드가 섞여 있지 않은지 본다(conflicting_env_pairs로 충돌 판정). manual_check_output(fail, cluster-level 관측).

**③ 친절 설명**

한 구획 안에 운영 앱과 개발 앱이 뒤섞여 있지 않은지 봅니다. 개발하다 실수로 운영 데이터를 건드리는 사고를 막기 위함이에요.

---

## R-2.8.3-03 — prod Secret이 dev에서 참조
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`prod_secret_used_by_dev==False` — production 라벨이 붙은 Secret을 개발/시험 워크로드가 참조하지 않는지 본다.

**③ 친절 설명**

운영용 비밀정보(Secret)를 개발 앱이 끌어다 쓰고 있지 않은지 봅니다. 운영 비밀번호가 개발 환경으로 새면 큰 위험이거든요.

---

# 2.9.1 변경관리

> 인증기준: 정보시스템의 변경(OS, 미들웨어, 응용프로그램, 네트워크 장비 등)에 대한 절차를 수립하여 변경 이력을 관리하고, 변경 전 시스템에 미치는 영향을 분석하여야 한다.

## R-2.9.1-01 — change-cause annotation 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

Deployment annotation `kubernetes.io/change-cause`가 존재하고, 최신 ReplicaSet에도 전파됐는지(`latest_replicaset_has_change_cause==True`) 본다.

**③ 친절 설명**

배포를 바꿀 때 '왜 바꿨는지(변경 사유)'가 기록돼 있는지 봅니다. 나중에 문제가 생기면 어떤 변경 때문인지 추적할 수 있어야 하니까요.

---

## R-2.9.1-02 — revisionHistoryLimit=0 (롤백 불가)
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`deployment.spec.revisionHistoryLimit>0` — 이전 ReplicaSet 이력을 보존해 롤백이 가능한지 본다(0이면 롤백 불가).

**③ 친절 설명**

배포 이력을 남겨 둬서 문제가 생겼을 때 이전 버전으로 되돌릴(롤백) 수 있는지 봅니다. 이력을 0으로 지워 두면 사고 시 복구가 안 돼요.

---

# 2.10.2 클라우드 보안

> 인증기준: 클라우드 서비스 이용 시 서비스 유형(IaaS, PaaS, SaaS 등)에 따른 보안 위험을 평가하고, 이에 맞는 보안대책을 수립·이행하여야 한다.

## R-2.10.2-08 — Namespace Pod Security Admission 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

Namespace의 Pod Security Admission 라벨 — `pod-security.kubernetes.io/enforce` 및 `audit`가 baseline 또는 restricted인지 본다. exception_check 예외.

**③ 친절 설명**

쿠버네티스가 위험한 설정의 컨테이너(예: 루트 권한·특권 모드)를 아예 못 뜨게 막는 '입국심사(PSA)'가 켜져 있는지 봅니다. baseline/restricted 등급이 걸려 있어야 위험한 Pod를 거를 수 있어요.

---

# 2.10.3 공개서버 보안

> 인증기준: 외부 네트워크에 공개되는 서버의 경우 내부 네트워크와 분리하고, 취약점 점검, 접근통제, 이상징후 모니터링 등 강화된 보호대책을 수립·이행하여야 한다.

## R-2.10.3-01 — LoadBalancer source range 미설정
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

LoadBalancer Service의 `spec.loadBalancerSourceRanges`가 설정되고(`!=None`), 0.0.0.0/0 전체 허용이 아닌 특정 IP 대역(`source_range_not_all_open==True`)인지 본다.

**③ 친절 설명**

외부에 공개되는 로드밸런서가 '아무나(0.0.0.0/0)'가 아니라 허용된 IP 대역에서만 접근되도록 제한돼 있는지 봅니다. 공개 입구일수록 출입을 좁혀야 안전해요.

---

## R-2.10.3-02 — 공개 Ingress WAF annotation 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`public_ingress_has_waf==True` — 공개 Ingress에 WAF(AWS WAFv2 ACL 또는 ModSecurity, waf_annotations) annotation이 있는지 본다.

**③ 친절 설명**

외부에 공개된 입구 앞에 웹 방화벽(WAF)이 붙어 있는지 봅니다. WAF는 SQL 인젝션 같은 웹 공격을 걸러 주는 1차 방어막이에요.

---

## R-2.10.3-03 — NodePort Service 공개 의도 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.10.3-03",
    "additional_review_items": [
      "발견된 NodePort가 의도된 공개인가",
      "VPC SG에서 노드의 NodePort 차단되어 있는가"
    ],
    "manual_check_areas": [
      "NodePort 사용 정책",
      "VPC Security Group 설정"
    ],
    "alternative_controls": [
      "VPC Security Group",
      "Network ACL"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.3",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "VPC SG/Network ACL에서 해당 NodePort가 외부로부터 차단",
      "의도된 공개로 NodePort 사용 정책상 승인·문서화됨"
    ]
  }
}
```

**② 무엇을 보는지**

NodePort Service에 `exposure-intent` 라벨(public/internal-only/debug)이 있는지 본다. manual_check_output(always): VPC SG/Network ACL로 차단됐는지, 의도된 공개인지 확인 안내(cluster-level).

**③ 친절 설명**

NodePort는 노드 포트를 직접 여는 방식이라 의도치 않게 외부 노출되기 쉬워요. 이 룰은 그런 노출이 '의도된 것'이라고 표시돼 있는지 봅니다. 실제 차단은 VPC 보안그룹으로 했을 수 있어 사람이 함께 확인합니다.

---

## R-2.10.3-04 — 공개 Ingress rate limit 미설정
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`public_ingress_has_rate_limit==True` — 공개 Ingress에 rate limit(rate_limit_annotations) annotation이 설정됐는지 본다.

**③ 친절 설명**

공개 입구에 '요청 속도 제한'이 걸려 있는지 봅니다. 짧은 시간에 폭주하는 요청(DDoS·과다요청)으로부터 서비스를 보호하기 위함이에요.

---

## R-2.10.3-05 — LoadBalancer 공개 의도 라벨 부재
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

LoadBalancer Service에 `exposure-intent` 라벨(public/internal-only)이 있거나 internal LB annotation이 있는지(`lb_has_internal_annotation_or_public_label==True`) 본다.

**③ 친절 설명**

로드밸런서가 '외부 공개인지 내부 전용인지' 의도가 명확히 표시돼 있는지 봅니다. 의도를 적어 두면 실수로 내부용이 외부에 열리는 걸 막을 수 있어요.

---

# 2.10.5 정보전송 보안

> 인증기준: 업무 목적으로 개인정보 및 중요정보를 전송할 경우 안전한 전송 정책을 수립하고, 전송 중 보호를 위한 기술적 대책을 적용하여야 한다.

## R-2.10.5-01 — 외부 공개 Ingress TLS 미설정
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.10.5-01",
    "additional_review_items": [
      "미설정 Ingress가 개인정보/중요정보 송수신 경로인가",
      "외부 LB에서 TLS 종료 + 클러스터 내 mTLS 구조인가"
    ],
    "manual_check_areas": [
      "송수신 인터페이스 목록",
      "개인정보 처리 시스템 흐름도"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "HTTP 통신으로 개인정보 송수신",
        "match": "direct"
      }
    ],
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
    "offcluster_satisfaction_conditions": [
      "외부 LB TLS 종료 + 클러스터 내 mTLS 구조",
      "해당 경로가 개인정보/중요정보 송수신 경로가 아님(송수신 인터페이스 목록 확인)"
    ]
  }
}
```

**② 무엇을 보는지**

외부 공개 Ingress의 `spec.tls`가 존재하고(`!=None`) 모든 host가 TLS로 커버되는지(`tls_covers_all_hosts==True`) 본다. manual_check_output(fail): 송수신 목록·흐름도 확인 안내.

**③ 친절 설명**

외부로 공개된 입구가 빠짐없이 HTTPS(TLS)로 암호화돼 있는지 봅니다. 일부 host만 암호화되고 나머지는 평문이면 그 틈으로 정보가 샐 수 있어요.

---

## R-2.10.5-03 — ExternalName Service 평문 endpoint
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.10.5-02",
    "additional_review_items": [
      "평문 호출이 비중요 외부 서비스인가",
      "중요 정보 송수신이면 https:// 변경 필요"
    ],
    "manual_check_areas": [
      "외부 호출 인터페이스 목록"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "외부 송수신 시 평문 전송",
        "match": "direct"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.5",
        "match_strength": "direct"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "평문 호출 대상이 개인정보/중요정보 비송수신 비중요 외부 서비스로 확인됨(중요정보면 https 전환 필요)"
    ]
  }
}
```

**② 무엇을 보는지**

`externalname_endpoint_is_tls==True` — ExternalName Service가 가리키는 외부 endpoint가 TLS(HTTPS)인지(tls_verification 기준) 본다. manual_check_output(fail) 동반.

**③ 친절 설명**

외부 시스템으로 연결되는 통로가 암호화(HTTPS)된 주소를 쓰는지 봅니다. 평문(HTTP)으로 외부와 데이터를 주고받으면 중간에 가로채일 수 있어요.

---

# 2.10.8 패치관리

> 인증기준: 소프트웨어, 운영체제, 보안장비 등의 보안 패치 적용을 위한 절차를 수립하고, 정기적으로 패치를 적용하여야 한다.

## R-2.10.8-01 — Node kubeletVersion EOL
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.10.8-01",
    "additional_review_items": [
      "EKS 지원 버전 정책과 비교",
      "패치 일정 계획 확인"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "EOL 시스템 운영",
        "match": "direct"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "direct"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "kubeletVersion이 EKS 지원 버전 범위 내이거나, 패치 일정 계획상 지원 버전 업그레이드가 결재·관리됨(EOL 운영이면 결함)"
    ]
  }
}
```

**② 무엇을 보는지**

`node_kubelet_version_supported==True` — Node의 kubeletVersion이 AWS EKS 지원 버전 범위 내인지(eol_policy 기준: EKS는 약 14개월 지원) 본다. manual_check_output(fail): 패치 일정/EOL 운영 여부 확인.

**③ 친절 설명**

클러스터 노드의 쿠버네티스 버전이 너무 낡아(EOL) 보안 패치가 더 이상 안 나오는 버전은 아닌지 봅니다. 지원 종료된 버전은 새 취약점이 나와도 못 막아요.

---

## R-2.10.8-02 — 이미지 태그 mutable
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.10.8-02",
    "additional_review_items": [
      "mutable 태그 정책이 회사 표준에 부합하는가",
      "패치 적용 시점 추적이 다른 방식으로 가능한가"
    ],
    "manual_check_areas": [
      "이미지 태그 정책",
      "CI/CD 빌드 추적 시스템"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "mutable 태그여도 CI/CD 빌드 추적 시스템으로 실제 배포 이미지·패치 시점 추적 가능"
    ]
  }
}
```

**② 무엇을 보는지**

`all_images_use_immutable_tag==True` — 모든 컨테이너 이미지가 latest/stable/dev 같은 mutable_tag_patterns가 아니라 버전 고정 태그/digest를 쓰는지 본다. manual_check_output(fail): 태그 정책·CI/CD 추적 확인.

**③ 친절 설명**

컨테이너 이미지를 `latest` 같은 '움직이는 태그'로 쓰면 같은 이름인데 내용이 계속 바뀌어, 지금 무엇이 돌고 있고 패치가 됐는지 추적이 안 돼요. 이 룰은 버전이 고정된 태그를 쓰는지 봅니다.

---

## R-2.10.8-03 — 이미지 digest 미고정
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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
  },
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.10.8-03",
    "additional_review_items": [
      "digest 미고정이 회사 표준에 부합하는가",
      "이미지 무결성을 다른 방식으로 보장하는가"
    ],
    "manual_check_areas": [
      "이미지 무결성 정책",
      "이미지 서명/검증 운영"
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "digest 미고정이어도 이미지 서명/검증(Cosign/Notation 등)으로 무결성 보장됨"
    ]
  }
}
```

**② 무엇을 보는지**

`all_images_pinned_by_digest==True` — 모든 이미지가 `@sha256:` digest로 고정됐는지 본다. manual_check_output(fail): 이미지 무결성/서명 검증 확인.

**③ 친절 설명**

이미지를 내용 지문(digest, @sha256:)으로 못 박아 두면 '내가 검증한 바로 그 이미지'가 도는 걸 보장할 수 있어요. 이 룰은 그렇게 무결성이 고정됐는지 봅니다.

---

## R-2.10.8-04 — 실행 중 이미지 알려진 취약점(CVE) 현황
*⬆️ R로 승격(자동 점검)*

**① 원본 JSON**

```json
{
  "rule_id": "R-2.10.8-04",
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
    "offcluster_satisfaction_conditions": [
      "발견된 CVE가 취약점 관리 정책상 예외 승인/완화조치로 처리됐거나 긴급 패치 프로세스로 조치(예정)됨"
    ],
    "k8s_only_check": true,
    "deferred": false
  },
  "promoted_from": "F-2.10.8-04",
  "manual_check_output": {
    "applies_when": "fail",
    "absorbed_from": "F-2.10.8-04",
    "additional_review_items": [
      "Trivy/Clair 등 이미지 스캔 도구 운영 여부",
      "Critical CVE 긴급 패치 프로세스",
      "취약점 관리 정책/기록"
    ],
    "manual_check_areas": [
      "취약점 관리 정책",
      "이미지 스캔 운영 현황"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "알려진 취약점 패치 미적용",
        "match": "direct"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.10.8",
        "match_strength": "direct"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "발견된 CVE가 취약점 관리 정책상 예외 승인/완화조치로 처리됐거나 긴급 패치 프로세스로 조치(예정)됨"
    ]
  }
}
```

**② 무엇을 보는지**

`cve_vulnerability_check` operator — 실행 중 이미지의 digest를 CVE 테이블과 조인(`cluster_pods.image_digest ⋈ cves`)해 알려진 취약점(특히 Critical/High)을 본다. F-2.10.8-04에서 R로 승격, 분모 포함.

**③ 친절 설명**

지금 돌고 있는 컨테이너 이미지에 '이미 알려진 보안 취약점(CVE)'이 들어 있는지 봅니다. 패치 안 된 알려진 구멍은 공격자가 가장 먼저 노리는 곳이에요. 데이터가 이미 있어 자동 점검으로 승격했습니다.

---

# 2.11.3 이상행위 분석 및 모니터링

> 인증기준: 네트워크 및 시스템에 대하여 이상행위를 탐지·분석하기 위한 모니터링 체계를 구축하고, 이상행위 발생 시 적시에 대응할 수 있도록 절차를 수립·이행하여야 한다.

## R-2.11.3-01 — prod 환경 shell exec 활동
*⚙️ 실측(K8s/증적)*

**① 원본 JSON**

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

**② 무엇을 보는지**

`prod_exec_detected==False` — 운영 namespace(prod_namespace_indicators)에서 Pod로의 exec(셸 접속, exec_detection) 활동이 탐지되지 않았는지 본다. alert_on_detection로 경보.

**③ 친절 설명**

운영 중인 컨테이너에 사람이 직접 들어가 셸 명령을 친(exec) 흔적이 있는지 봅니다. 운영 환경에 비인가로 손을 대는 건 사고·내부위협의 신호거든요.

---

## R-2.11.3-02 — 운영 환경 Shell 활동 관찰 (eBPF)
*⏸️ 보류(eBPF 연동 후 활성)*

**① 원본 JSON**

```json
{
  "rule_id": "R-2.11.3-02",
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
    "offcluster_satisfaction_conditions": [
      "탐지된 shell exec이 인가된 운영 작업(결재·SSM Session Manager/Teleport/PAM 기록)으로 확인",
      "이상행위 탐지 도구(Falco/Tetragon)·로그 보관 정책 운영 중"
    ],
    "k8s_only_check": true,
    "deferred": true,
    "deferred_reason": "행위 관측(운영 shell exec). eBPF(Falco/Tetragon) 파이프라인 연동 후 활성화"
  },
  "deferred_from": "F-2.11.3-01",
  "manual_check_output": {
    "applies_when": "always",
    "absorbed_from": "F-2.11.3-01",
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
    "alternative_controls": [
      "SSM Session Manager",
      "Teleport",
      "외부 PAM 도구"
    ],
    "kisa_defect_case_refs": [
      {
        "case_number": null,
        "description": "모니터링 사각지대 - 운영 중 비정상 활동 미감지",
        "match": "partial"
      }
    ],
    "compliance_mappings": [
      {
        "framework": "ISMS-P",
        "item": "2.11.3",
        "match_strength": "indirect"
      }
    ],
    "offcluster_satisfaction_conditions": [
      "탐지된 shell exec이 인가된 운영 작업(결재·SSM Session Manager/Teleport/PAM 기록)으로 확인",
      "이상행위 탐지 도구(Falco/Tetragon)·로그 보관 정책 운영 중"
    ]
  }
}
```

**② 무엇을 보는지**

`prod_shell_exec_detection` operator로 운영 shell 활동을 eBPF 관찰하려는 룰이나 **deferred=true(보류)** — eBPF(Falco/Tetragon) 파이프라인 연동 전이라 분모 제외.

**③ 친절 설명**

운영 환경의 셸 활동을 커널 수준(eBPF)으로 깊게 관찰하려는 룰이에요. 다만 Falco/Tetragon 같은 관측 도구 연동 전이라 지금은 '보류' 상태이고, 연동되면 켜집니다.

---
