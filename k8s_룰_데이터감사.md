# k8s 실측 룰 데이터 감사표 (61룰)

각 룰이 참조하는 필드가 **실제로 수집되는 DB 컬럼과 맞는지** 대조해 분류했다. 결론: 그대로 신뢰 가능한 룰은 일부뿐이고, 다수가 데이터 미수집으로 **항상 미준수/항상 준수/확인불가**로 흐른다.

## 요약

| 상태 | 개수 | 의미 |
|---|---|---|
| ✅ 동작 | 14 | 데이터 수집됨, 실제 판정 가능 |
| ✅ 동작(부분/조건부) | 4 | 핵심은 동작, 일부 항목은 데이터 한계 |
| ✅ 동작(조건부) | 1 | 라벨 등 조건 충족 시 동작 |
| ⚠️ 확인불가(NO_DATA) | 6 | 게이트가 NO_DATA로 차단(미수집 라벨/annotation 참조) |
| 🔴 항상 미준수 | 10 | 게이트 통과하나 데이터 미수집 → 리소스 존재 시 무조건 위반(거짓 양성) |
| 🔵 항상 준수 | 3 | 데이터 미수집 → 위반을 절대 못 잡음(거짓 음성) |
| 🧩 증적/RAG | 14 | 클러스터 스냅샷이 아닌 업로드 증적 필요 |
| 🧩 증적+오결선 | 1 | 증적 필요 + 평가함수 오결선 |
| 📋 리포트 | 4 | 판정 없는 인벤토리/리포트 |
| ⬆️ 승격 | 2 | F→R 승격(자동 점검) |
| ⏸️ 보류 | 2 | eBPF 연동 전 보류 |

**합계 61룰.** 실제로 신뢰성 있게 도는 건 ✅류(약 19개)뿐. 🔴+🔵+⚠️ (19개)는 **수집 파이프라인을 고치기 전엔 결과를 믿으면 안 된다.**

## 상태별 목록

### ✅ 동작 — 14개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.1.3-01` | `evalWorkloadOwnerAnnotation` | pod.metadata.annotations.isms-p/owner·owner-team | cluster_pods.annotations ✅ | Pod owner/owner-team annotation 점검. (workload→pod로 교정 완료) |
| `R-2.5.1-01` | `evalDefaultServiceAccount` | pod.spec.serviceAccountName | cluster_pods.service_account ✅ | default SA 사용 여부 판정. |
| `R-2.5.2-01` | `evalPredictableSAName` | SA 이름 | cluster_pods.service_account ✅ | 추측 가능한 SA 이름 패턴 판정. |
| `R-2.5.2-02` | `evalGenericSANamePattern` | SA 이름 | cluster_pods.service_account ✅ | 일반(generic) SA 이름 패턴 판정. |
| `R-2.5.5-01` | `evalServiceAccountPrivileges` | roles/bindings | cluster_(cluster_)roles(_bindings) ✅ | cluster-admin·와일드카드·전체 Secret 권한 판정. |
| `R-2.5.5-02` | `evalDangerousVerbCombos` | roles/bindings | cluster_(cluster_)roles(_bindings) ✅ | 위험 verb 조합 판정. |
| `R-2.6.1-02` | `evalNetworkPolicy` | NetworkPolicies + pod | cluster_network_policies ✅ | default-deny + 매칭 정책 판정. |
| `R-2.6.1-04` | `evalCrossNSTraffic` | NetworkPolicies + pod | cluster_network_policies ✅ | cross-namespace egress 통제 판정. |
| `R-2.6.7-01` | `evalEgressPolicy` | NetworkPolicies + pod | cluster_network_policies ✅ | egress 정책/default-deny 판정. |
| `R-2.10.5-01` | `evalExternalIngressTLS` | ingress.spec.tls | cluster_ingresses.tls ✅ | 외부 Ingress TLS 설정/커버리지 판정. |
| `R-2.10.5-03` | `evalExternalNamePlaintext` | service external_name | cluster_services.external_name ✅ | ExternalName 평문 endpoint 판정. |
| `R-2.10.8-01` | `evalNodeKubeletVersion` | node kubelet_version | cluster_nodes.kubelet_version ✅ | kubelet EOL 판정. |
| `R-2.10.8-02` | `evalImageTagMutable` | pod containers images | cluster_pods.containers ✅ | mutable 태그 판정. |
| `R-2.10.8-03` | `evalImageDigest` | pod containers images | cluster_pods.containers ✅ | digest 고정 판정. |

### ✅ 동작(부분/조건부) — 4개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.6.1-01` | `evalHostNamespace` | pod.spec.hostNetwork/hostPID/hostIPC | cluster_pods.host_network ✅ (hostPID/IPC 미수집) | hostNetwork는 판정 가능. hostPID/hostIPC는 컬럼 없어 항상 통과 처리. |
| `R-2.6.1-03` | `evalCNIDaemonSet` | Workloads(DaemonSet) | cluster_workloads(kind,containers) ✅ | CNI DaemonSet 존재/강제옵션. containers env 적재 범위에 의존. |
| `R-2.7.1-03` | `evalIngressTLS` | ingress.spec.tls (+ALB 증적) | cluster_ingresses.tls ✅ (ALB는 증적) | Ingress TLS는 실측. ALB listener/ssl_policy 부분은 증적 업로드 필요. |
| `R-2.8.3-02` | `evalNSEnvMixing` | Workloads env | cluster_workloads.template_labels ✅ | namespace 내 env 혼재. Pod 템플릿에 env 라벨 있을 때 동작. |

### ✅ 동작(조건부) — 1개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.5.1-03` | `evalCrossTeamSASharing` | SA 공유(팀 식별) | cluster_pods/workloads ✅ (팀 라벨 의존) | 팀 식별 라벨이 있어야 정확. 라벨 없으면 판정 약함. |

### ⚠️ 확인불가(NO_DATA) — 6개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-1.2.1-01` | `evalNamespaceLabels` | namespace.metadata.labels.* | cluster_namespaces에 labels 컬럼 없음 ❌ | 게이트가 NO_DATA로 차단. namespace 라벨 미수집. |
| `R-1.2.2-01` | `evalExternalDepLabel` | externalname_service.metadata.labels.* | cluster_services에 labels 컬럼 없음 ❌ | 게이트 NO_DATA. Service 라벨 미수집. |
| `R-1.2.2-02` | `evalIngressFlowRegistered` | ingress.metadata.annotations.* | cluster_ingresses에 annotations 컬럼 없음 ❌ | 게이트 NO_DATA. Ingress annotation 미수집. |
| `R-2.1.3-02` | `evalSecurityClassLabel` | workload.metadata.labels.security-class | cluster_workloads에 labels 컬럼 없음 ❌ | 게이트 NO_DATA. (eval은 pod 라벨을 읽으므로 pod.metadata.labels로 교정 시 동작 가능) |
| `R-2.8.3-01` | `evalWorkloadEnvLabel` | workload.metadata.labels.env | cluster_workloads에 labels 컬럼 없음 ❌ | 게이트 NO_DATA. (pod.metadata.labels.env로 교정 시 동작 가능) |
| `R-2.10.2-08` | `evalNamespacePSA` | namespace.metadata.labels.pod-security… | cluster_namespaces에 labels 컬럼 없음 ❌ | 게이트 NO_DATA. PSA 라벨은 namespace 라벨 수집해야 점검 가능. |

### 🔴 항상 미준수 — 10개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.5.1-02` | `evalSAOwnerLabel` | serviceaccount.metadata.labels.* | cluster_service_accounts에 labels 컬럼 없음 ❌ | SA 라벨 미수집 → 전용 SA 있으면 항상 미준수. |
| `R-2.6.3-01` | `evalIngressAuth` | ingress auth annotation | cluster_ingresses에 annotations 없음 ❌ | 인증 annotation 미수집 → Ingress 있으면 항상 미준수. |
| `R-2.6.3-02` | `evalMTLS` | namespace istio 라벨 + PeerAuth | cluster_namespaces 라벨 없음 ❌ | istio-injection 라벨 미수집 → mTLS STRICT 확인 불가, 사실상 항상 미준수. |
| `R-2.9.1-01` | `evalChangeCause` | deployment.metadata.annotations.change-cause | cluster_workloads에 annotations 없음(코드가 {}로 박음) ❌ | Deployment 있으면 항상 미준수(거짓 양성). |
| `R-2.10.3-01` | `evalLBSourceRange` | service loadBalancerSourceRanges | cluster_services에 해당 컬럼 없음 ❌ | LB 있으면 ranges 빈 값 → 항상 미준수. |
| `R-2.10.3-02` | `evalIngressWAF` | ingress WAF annotation | cluster_ingresses annotations 없음 ❌ | WAF annotation 미수집 → TLS Ingress 있으면 항상 미준수. |
| `R-2.10.3-03` | `evalNodePortExposureLabel` | nodeport service 라벨 | cluster_services 라벨 없음 ❌ | NodePort 있으면 라벨 못 읽어 항상 미준수. (※ eval은 키 isms-p/exposure 사용) |
| `R-2.10.3-04` | `evalIngressRateLimit` | ingress rate-limit annotation | cluster_ingresses annotations 없음 ❌ | rate-limit annotation 미수집 → Ingress 있으면 항상 미준수. |
| `R-2.10.3-05` | `evalLBExposureLabel` | lb service 라벨 | cluster_services 라벨 없음 ❌ | LB 있으면 라벨 못 읽어 항상 미준수. |
| `R-2.11.3-01` | `evalProdShellExec` | eBPF 이벤트 + namespace 라벨 | eBPF 미수집 + namespace 라벨 없음 ❌ | prod namespace 식별·exec 이벤트 미수집 → 사실상 동작 안 함. |

### 🔵 항상 준수 — 3개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.7.1-02` | `evalConfigMapSecrets` | configmap 내용 | cluster_configmaps는 mounted_by_pods만, 내용 미수집 ❌ | ConfigMap 본문 미수집 → 평문 비밀값 절대 못 잡음 → 항상 준수. |
| `R-2.8.3-03` | `evalCrossEnvSecretRef` | secret env 라벨 | cluster_secrets에 labels 없음 ❌ | Secret env 라벨 미수집 → prod-secret 비교 불가 → 항상 준수. |
| `R-2.9.1-02` | `evalRevisionHistoryLimit` | deployment.spec.revisionHistoryLimit | cluster_workloads에 spec 없음 ❌ | revisionHistoryLimit 미수집 → '기본값 10' 취급 → 항상 준수(롤백 불가 못 잡음). |

### 🧩 증적/RAG — 14개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.5.4-03` | `(rag)` | OS 패스워드 정책 | 증적 업로드 | 리눅스 /etc/login.defs·pam 설정 증적 필요. |
| `R-2.5.4-04` | `(rag)` | AD 정책 | 증적 업로드 | Active Directory 정책 증적 필요. |
| `R-2.5.4-05` | `(rag)` | IAM 패스워드 정책 | 증적 업로드 | AWS IAM account password policy 증적 필요. |
| `R-2.5.4-06` | `(rag)` | DB 계정 정책 | 증적 업로드 | Oracle/MySQL 정책 증적 필요. |
| `R-2.5.4-07` | `(rag)` | WAS 정책 | 증적 업로드 | WAS 정책 증적 필요. |
| `R-2.5.4-08` | `(rag)` | 가입/변경 화면 | 증적 업로드 | 화면 동작 증적/의미판정 필요. |
| `R-2.5.4-09` | `(rag)` | 변경주기 통계 | 증적 업로드 | 계정 변경일 통계 증적 필요. |
| `R-2.5.4-10` | `(rag)` | 임시비번 강제변경 코드 | 증적 업로드 | 소스/코드 증적 필요. |
| `R-2.5.4-11` | `(rag)` | 임시비번 강제변경 화면 | 증적 업로드 | 화면 증적 필요. |
| `R-2.5.4-12` | `(rag)` | 미변경자 목록 | 증적 업로드 | 계정 통계 증적 필요. |
| `R-2.5.4-13` | `(rag)` | DB 비번 저장형태 | 증적 업로드 | 해시 형태 증적 필요. |
| `R-2.5.4-14` | `(rag)` | MFA 정책 | 증적 업로드 | MFA 설정 증적 필요. |
| `R-2.5.4-15` | `(rag)` | 로그인 화면 | 증적 업로드 | 로그인 화면 증적 필요. |
| `R-2.7.1-01` | `evalSecretEncryption` | EKS Secret etcd 암호화 | EKS encryption config 증적 | KMS/encryption 증적 필요(클러스터 스냅샷 아님). |

### 🧩 증적+오결선 — 1개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.7.1-04` | `evalIngressTLS(오결선)` | KMS 키 상태/로테이션 | 증적 업로드 + 평가함수 오결선 | KMS 점검이어야 하나 switch가 evalIngressTLS로 잘못 연결됨 → KMS 점검 안 함. |

### 📋 리포트 — 4개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-1.2.1-02` | `inventory_report` | - | cluster_* 인벤토리 | 자산 인벤토리 리포트(판정 없음). |
| `R-1.2.2-03` | `traffic_graph_report` | - | pod 통신 관계 | 통신 인벤토리 리포트. |
| `R-1.2.2-04` | `external_dependency_report` | - | 외부 연계 | 외부 의존성 리포트. |
| `R-2.1.3-03` | `change_activity_report` | - | 변경 활동 | 변경 활동 리포트. |

### ⬆️ 승격 — 2개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.5.1-04` | `orphan_serviceaccount` | SA − bindings | cluster_service_accounts + bindings ✅ | 미사용 SA 탐지(자동). 데이터 있음 → 동작. |
| `R-2.10.8-04` | `cve_vulnerability_check` | image_digest ⋈ cves | cluster_pods.containers + cves 테이블 | CVE 점검. cves 테이블 적재 시 동작. |

### ⏸️ 보류 — 2개

| 룰 | 평가함수 | 참조 데이터 | 실제 수집 / 근거 | 동작 설명 |
|---|---|---|---|---|
| `R-2.6.7-02` | `external_domain_traffic_report` | eBPF DNS | 미수집(보류) | eBPF/DNS 파이프라인 연동 후 활성. |
| `R-2.11.3-02` | `prod_shell_exec_detection` | eBPF shell | 미수집(보류) | eBPF(Falco/Tetragon) 연동 후 활성. |

## 고치는 방향 (카테고리별)

- **⚠️ 확인불가 / 🔴 / 🔵 (라벨·annotation 미수집)**: 수집 에이전트가 `cluster_namespaces`·`cluster_services`·`cluster_ingresses`·`cluster_workloads`·`cluster_service_accounts`·`cluster_secrets`에 **labels/annotations(JSONB) 컬럼을 추가 적재**하면 다수가 바로 동작. (스키마 + assembler + 에이전트 수집 동시 수정)
- **🔴 R-2.9.1-01 / 🔵 R-2.9.1-02**: `cluster_workloads`에 **annotations·spec(revisionHistoryLimit)** 적재 필요. ReplicaSet 테이블도 없어 `latest_replicaset_has_change_cause`는 죽은 인디케이터.
- **🔵 R-2.7.1-02**: `cluster_configmaps`에 **data(내용)** 미수집 → 본문 적재해야 평문 비밀값 점검 가능.
- **🧩 R-2.7.1-04**: 평가함수가 `evalIngressTLS`로 **오결선** → KMS 점검 함수로 교정 필요.
- **🧩 2.5.4-* (13개)**: 본디 클러스터 점검이 아니라 OS/AD/IAM/DB/WAS **증적 업로드** 기반 → judgment_source 분류를 재검토(텍스트/증적 레이어로).
- **⏸️ deferred 2 / ⬆️ 승격 2**: 승격(orphan SA, CVE)은 데이터만 적재되면 동작; deferred는 eBPF 파이프라인 대기.
