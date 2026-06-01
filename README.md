# VARA Backend

Go + Gin + PostgreSQL(+pgvector) + Redis 기반 VARA SaaS 백엔드.

## 구조

```
vara-backend/
├── cmd/server/main.go              # 엔트리포인트 (얇게 유지)
├── internal/                       # 외부 import 차단
│   ├── config/                     # env, yaml 로딩
│   ├── server/                     # HTTP 서버 + graceful shutdown + 라우팅 + mTLS
│   ├── middleware/                 # jwt / rbac / tenant / logger / recovery
│   ├── domain/                     # 순수 도메인 모델 (의존성 없음)
│   │   ├── agent/ auth/ cve/ ismsp/ pod/ scoring/ tenant/ topology/ dashboard/
│   ├── handler/                    # HTTP 핸들러 (도메인별 분리)
│   ├── service/                    # 비즈니스 로직
│   ├── repository/
│   │   ├── postgres/               # RDB 저장소
│   │   └── vector/                 # pgvector 저장소
│   ├── platform/                   # 외부 시스템 어댑터
│   │   ├── cache/                  # Redis
│   │   ├── trivy/ ebpf/ embedding/ k8s/ provisioner/
│   └── rbacchain/                  # RBAC 권한상승 분석 엔진 (snapshot/directperm/fixpoint/sareport/loader, rules 내장)
├── pkg/                            # 외부 공개 가능 유틸 (jwt / crypto / errs)
├── api/openapi.yaml                # API 명세
├── migrations/                     # 001 ~ 020 (cluster-reader / scoring / rbac-chain 등)
│   ├── 001_init.up.sql
│   ├── 002_pgvector.up.sql
│   └── 020_rbac_chain.up.sql       # RBAC 권한상승 분석 4개 테이블
├── deployments/
│   ├── docker/Dockerfile
│   └── k8s/                        # Helm chart / manifests
├── scripts/
├── test/                           # E2E / 통합 테스트
├── Makefile
├── docker-compose.yml
└── go.mod
```

## 로컬 실행

```bash
cp .env.example .env
docker-compose up --build
# 또는
make run
```

기동되면:
- 백엔드: http://localhost:8080
- PostgreSQL: localhost:5432
- Redis: localhost:6379

## DBeaver 접속

- Host: `localhost` / Port: `5432` / Database: `vara` / User: `vara` / Password: `changeme`

`migrations/001_init.up.sql`은 PostgreSQL 컨테이너 첫 기동 시 자동 실행됩니다.
`002_pgvector.up.sql`은 pgvector 확장이 설치된 PostgreSQL에서만 동작합니다 (운영은 RDS pgvector 또는 `pgvector/pgvector` 이미지 사용).

## 엔드포인트 (현재 동작)

| Method | Path | 설명 |
|---|---|---|
| GET | `/healthz` | DB 포함 헬스 체크 |
| POST | `/api/v1/agents/cluster-reader/pod-events` | Cluster Reader Agent |
| POST | `/api/v1/agents/ebpf/traffic` | eBPF Agent |
| POST | `/api/v1/agents/sbom` | SBOM 적재 |
| POST | `/api/v1/scoring/rbac-chain/compute` | RBAC 권한상승 분석 실행 (body: `{"cluster_name":"..."}`) |
| GET | `/api/v1/scoring/rbac-chain/clusters/:cluster_name` | 분석 요약 + SA별 결과 |
| GET | `/api/v1/scoring/rbac-chain/clusters/:cluster_name/sa/:namespace/:name` | SA 1개 상세(경로 포함) |

전체 API 명세는 [api/openapi.yaml](api/openapi.yaml) 참고.

## 운영 배포 (EC2 + RDS + ElastiCache)

1. RDS PostgreSQL(pgvector 확장 활성화) 생성, 같은 VPC private subnet에 배치
2. ElastiCache Redis 생성 (또는 EC2 내 Docker)
3. EC2에서 `docker build -f deployments/docker/Dockerfile -t vara-backend .` 후 환경변수만 RDS/ElastiCache 엔드포인트로 바꿔서 실행
4. 보안그룹: Agent들의 SG에서만 8080 인바운드 허용

```bash
docker run -d -p 8080:8080 \
  -e POSTGRES_HOST=<RDS_ENDPOINT> \
  -e POSTGRES_PASSWORD=<from secrets manager> \
  -e POSTGRES_SSLMODE=require \
  -e REDIS_ADDR=<ELASTICACHE_ENDPOINT>:6379 \
  vara-backend
```

---

## GRC Compliance Findings (ISMS-P 자동 점검)

### 개요

클러스터 스냅샷(Pod, Service, Ingress, RBAC, NetworkPolicy, Node, eBPF 등)을 기반으로 ISMS-P 인증심사 항목을 자동 점검하는 Finding 평가 엔진.

- **활성 Finding 룰**: 27개
- **평가 방식**: `operator` 기반 조건 매칭 (JSON condition → Go evaluator 디스패치)
- **Verdict 유형**: `compliant_indicator`, `potential_finding`, `needs_review`, `additional_evidence`

### 파일 구조

| 파일 | 역할 |
|------|------|
| `internal/service/finding_defaults.go` | 27개 Finding 정의 (Go 구조체, `DefaultFindings()`) |
| `migrations/021_compliance_findings.up.sql` | DB 시드 데이터 (27개 INSERT ON CONFLICT DO NOTHING) |
| `internal/service/finding_evaluator.go` | 평가 엔진 — operator별 evaluator 함수 |
| `internal/service/pod_graph_evaluator.go` | Pod 단위 룰 평가 엔진 |
| `internal/service/pod_graph_eval_rules.go` | Pod 룰 개별 평가 함수 |
| `internal/service/cluster_pod_assembler.go` | DB Row → PodGraphRequest 변환 |
| `rulesets/isms_p_*_pod_ruleset.json` | Pod 룰셋 JSON (17개 항목) |
| `testdata/findings_dataset.json` | Finding 테스트 데이터셋 (20개 룰 x 4 시나리오) |

### 활성 Finding 목록 (27개)

| Finding ID | ISMS-P 항목 | 제목 | Operator |
|------------|-------------|------|----------|
| F-1.2.1-K8S-01 | 1.2.1 | 클러스터 자산 인벤토리 | `inventory_report` |
| F-1.2.2-K8S-01 | 1.2.2 | 클러스터 내부 통신 관계 인벤토리 | `traffic_graph_report` |
| F-1.2.2-K8S-02 | 1.2.2 | 외부 의존성 발견 | `external_dependency_report` |
| F-2.1.3-K8S-01 | 2.1.3 | Pod 책임자 정보 부재 | `any_owner_indicator_exists` |
| F-2.1.3-K8S-02 | 2.1.3 | 자산 변경 활동 감지 | `change_activity_report` |
| F-2.5.1-K8S-01 | 2.5.1 | default ServiceAccount 사용 발견 | `in_set` |
| F-2.5.1-K8S-02 | 2.5.1 | 미사용(orphan) ServiceAccount 발견 | `orphan_serviceaccount` |
| F-2.5.2-K8S-01 | 2.5.2 | 추측 가능한 명칭의 SA | `regex_match` |
| F-2.5.2-K8S-02 | 2.5.2 | 추측 가능한 명칭의 SA (패턴2) | `regex_match` |
| F-2.5.5-K8S-01 | 2.5.5 | 클러스터 최고 권한 보유 SA | `any_of` |
| F-2.5.5-K8S-02 | 2.5.5 | 위험 RBAC 권한 보유 SA | `any_dangerous_verb` |
| F-2.6.1-K8S-01 | 2.6.1 | NetworkPolicy default-deny 적용 현황 | `default_deny_coverage_report` |
| F-2.6.1-K8S-02 | 2.6.1 | CNI NetworkPolicy 강제 상태 | `daemonset_exists` |
| F-2.6.1-K8S-03 | 2.6.1 | Cross-namespace 통신 통제 현황 | `cross_ns_traffic_control_report` |
| F-2.6.7-K8S-01 | 2.6.7 | Pod egress 통제 현황 | `egress_policy_applied` |
| F-2.6.7-K8S-02 | 2.6.7 | 실제 외부 도메인 접속 관찰 (eBPF) | `external_domain_traffic_report` |
| F-2.7.1-K8S-01 | 2.7.1 | Ingress TLS 적용 현황 | `field_non_empty` |
| F-2.8.3-K8S-01 | 2.8.3 | 환경 라벨 적용 현황 | `label_value_in` |
| F-2.8.3-K8S-02 | 2.8.3 | 환경 혼재 namespace 발견 | `namespace_env_homogeneous` |
| F-2.10.3-K8S-03 | 2.10.3 | NodePort 노출 현황 | `field_equals` |
| F-2.10.5-K8S-01 | 2.10.5 | 외부 공개 Ingress TLS 현황 | `field_non_empty` (scope: external_only) |
| F-2.10.5-K8S-02 | 2.10.5 | ExternalName Service 평문 호출 | `all_of` |
| F-2.10.8-K8S-01 | 2.10.8 | Node Kubernetes 버전 현황 | `kubelet_version_check` |
| F-2.10.8-K8S-02 | 2.10.8 | 이미지 태그 안정성 현황 | `tag_mutable_check` |
| F-2.10.8-K8S-03 | 2.10.8 | 이미지 디지스트 고정 현황 | `digest_present` |
| F-2.10.8-K8S-04 | 2.10.8 | 실행 중 이미지 알려진 취약점(CVE) 현황 | `cve_vulnerability_check` |
| F-2.11.3-K8S-01 | 2.11.3 | 운영 환경 Shell 활동 관찰 | `prod_shell_exec_detection` |

### 주요 설계 결정

**F-2.7.1 vs F-2.10.5 TLS 점검 범위 분리**
- F-2.7.1-K8S-01 (암호정책): 클러스터 내 **전체 Ingress**의 TLS 설정 점검
- F-2.10.5-K8S-01 (정보전송 보안): **외부 공개 Ingress만** 점검 (`scope: "external_only"`)
- 외부/내부 판별: ALB scheme annotation(`alb.ingress.kubernetes.io/scheme`), NLB scheme annotation, ingressClassName에 "internal" 포함 여부. 기본값은 external (보수적 판단)

**F-2.5.5-K8S-02 와일드카드 SA 중복 제거**
- F-2.5.5-K8S-01이 이미 cluster-admin/와일드카드 권한 SA를 검출
- F-2.5.5-K8S-02(위험 RBAC 패턴)에서 동일 SA가 다시 보고되지 않도록 `identifyWildcardSAs()` 헬퍼로 제외

### 삭제된 룰 (9개, DB 컬럼 미수신으로 비활성)

| Finding ID | 사유 |
|------------|------|
| F-1.2.1-K8S-02 | `namespaces.labels` 미수신 |
| F-2.6.3-K8S-01 | `ingresses.annotations` 미수신 |
| F-2.8.3-K8S-03 | `secrets.labels` 미수신 |
| F-2.9.1-K8S-01 | `workloads.annotations` 미수신 |
| F-2.9.1-K8S-02 | `revisionHistoryLimit` 컬럼 없음 |
| F-2.10.2-K8S-01 | `namespaces.labels` 미수신 |
| F-2.10.3-K8S-01 | `services` 컬럼 없음 (LB sourceRanges) |
| F-2.10.3-K8S-02 | `ingresses.annotations` 미수신 |
| F-2.10.3-K8S-04 | `ingresses.annotations` 미수신 |
