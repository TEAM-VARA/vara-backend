# VARA GRC Service — ISMS-P 자동 점검 시스템 핸드오프 문서

> 다른 Claude 인스턴스가 이 프로젝트를 이어받기 위한 컨텍스트 정리 문서
> 최종 갱신: 2026-05-22

---

## 0. TL;DR

VARA 팀의 **SBOM/AI 워크로드 보안 솔루션**에 GRC(Governance, Risk, Compliance) 서비스를 추가.
**ISMS-P 인증 항목 10개, 총 100개 룰**로 회사 증적을 받아 자동으로 준수/미준수 판단하는 시스템.
Go/Gin 백엔드 + PostgreSQL(pgvector) + BGE-M3 임베딩 서버 + Redis 캐싱.

---

## 1. 프로젝트 개요

### 1.1 아키텍처

```
[고객 증적 업로드]  →  [형식별 추출]  →  [룰 평가]  →  [준수/미준수 + 근거]
   PDF·PNG·JSON         OCR/PDF/JSON       100개 룰      + K8s 자원별 위반 위치
   CSV·TXT·YAML         + 임베딩 생성       4가지 방식     + 임베딩 유사도 2차 검증
```

### 1.2 기술 스택

| 항목 | 기술 |
|------|------|
| 백엔드 | Go 1.22+ / Gin |
| DB | PostgreSQL 16 + pgvector 확장 |
| 임베딩 | BGE-M3 (1024차원) — Python FastAPI 서버 |
| 캐싱 | Redis 7 |
| 배포 | Docker Compose (EC2) |
| OCR | Tesseract (컨테이너 내장) |
| PDF | pdftotext CLI |

### 1.3 4가지 판정 방식

| 방식 | 적용 | 설명 |
|------|------|------|
| `structured_match` | K8s/시스템 설정 JSON | field/op/value 비교 + normalizer |
| `semantic_match` | 정책 문서 PDF/텍스트 | 키워드 매칭 + 임베딩 유사도 2차 검증 |
| `regex_match` | 해시 형식 검증 | 정규식 패턴 매칭 |
| `aggregated_statistics` | 계정/변경 통계 CSV | 임계값 기반 집계 |

추가로 OCR 기반 화면 캡처 평가(`evaluateOCRKeywordMatch`)도 지원.

---

## 2. ISMS-P 항목 및 룰 구성 (10개 항목, 100개 룰)

| 항목 | 이름 | 룰 수 | 룰셋 파일 |
|------|------|-------|-----------|
| 1.1.4 | 범위 설정 | 12 | `rulesets/isms_p_1.1.4_ruleset.json` |
| 1.2.1 | 정보자산 식별 | 10 | `rulesets/isms_p_1.2.1_ruleset.json` |
| 1.2.2 | 현황 및 흐름분석 | 10 | `rulesets/isms_p_1.2.2_ruleset.json` |
| 1.2.3 | 위험 평가 | 10 | `rulesets/isms_p_1.2.3_ruleset.json` |
| 1.3.1 | 보호대책 구현 | 10 | `rulesets/isms_p_1.3.1_ruleset.json` |
| 2.2.1 | 주요 직무자 지정 및 관리 | 10 | `rulesets/isms_p_2.2.1_ruleset.json` |
| 2.2.2 | 직무 분리 | 10 | `rulesets/isms_p_2.2.2_ruleset.json` |
| 2.2.5 | 퇴직 및 직무변경 관리 | 10 | `rulesets/isms_p_2.2.5_ruleset.json` |
| 2.2.6 | 보안 위반 시 조치 | 10 | `rulesets/isms_p_2.2.6_ruleset.json` |
| 2.5.4 | 비밀번호 관리 | 15 | `rulesets/isms_p_2.5.4_ruleset.json` |

---

## 3. 디렉토리 구조

```
vara-backend/
├── cmd/server/main.go                    # 엔트리포인트
├── internal/
│   ├── domain/grc/
│   │   ├── models.go                     # Check, RuleResult, Violation, K8sSource, EvidenceFile 등
│   │   └── k8s_source_test.go
│   ├── handler/
│   │   └── grc_handler.go                # HTTP 핸들러 (CreateCheck, GetCheck, ListEvidence 등)
│   ├── repository/postgres/
│   │   └── grc_repo.go                   # DB CRUD (checks, rule_results, violations, evidence_files)
│   ├── service/
│   │   ├── grc_service.go                # 핵심 비즈니스 로직 (CreateCheck, processCheck 워커)
│   │   ├── grc_ruleset.go                # 룰셋 JSON 로딩 + Rule 구조체
│   │   ├── grc_embedding_eval.go         # 임베딩 유사도 평가 + 2차 검증
│   │   ├── grc_resource_extractor.go     # K8s 자원 단위 위반 추출기 (14개 룰)
│   │   ├── grc_ocr_parser.go             # OCR 텍스트 → 구조화 파싱
│   │   ├── grc_k8s_attribution.go        # 증적↔K8s 소스 매핑
│   │   ├── ismsp_fixture_normalize.go    # structured_match 용 데이터 정규화
│   │   ├── grc_rule_evaluate.go          # 단일 룰 평가 (테스트용)
│   │   └── grc_rule_fixtures_golden_test.go  # 45개 fixture 골든 테스트
│   ├── server/
│   │   ├── server.go                     # 서버 초기화 (DI)
│   │   └── router.go                     # 라우트 정의
│   └── platform/
│       ├── embedding/embedding.go        # BGE-M3 HTTP 클라이언트
│       ├── ocr/ocr.go                    # Tesseract OCR 래퍼
│       └── pdfext/pdfext.go              # pdftotext 래퍼
├── embedding-server/
│   └── embedding_server.py               # FastAPI BGE-M3 서버 (단일/배치 지원)
├── rulesets/                             # 10개 항목 룰셋 JSON
├── evidence_samples/                     # 항목별 증적 샘플
├── migrations/                           # PostgreSQL 마이그레이션 (001~008)
├── ISMS-P_rule_testdata         # 골든 테스트 fixture (45개)
├── docker-compose.yml                    # Docker Compose (backend, postgres, redis, embedding)
└── deployments/docker/Dockerfile         # 멀티스테이지 Go 빌드
```

---

## 4. API 엔드포인트

기본 경로: `/api/v1`

| Method | Path | 설명 |
|--------|------|------|
| POST | `/compliance/checks` | 증적 업로드 + 비동기 체크 생성 |
| GET | `/compliance/checks` | 체크 목록 조회 |
| GET | `/compliance/checks/:check_id` | 체크 결과 상세 (rule_results, violations 포함) |
| GET | `/compliance/checks/:check_id/evidence` | 증적 파일 목록 |
| GET | `/rulesets` | 지원 항목 목록 |
| GET | `/rulesets/:item_id` | 룰셋 상세 |
| POST | `/compliance/cloud-environments` | K8s 환경 데이터 등록 |
| GET | `/compliance/cloud-environments` | 환경 데이터 목록 |

### 4.1 증적 업로드 예시

```bash
curl -X POST http://localhost:8080/api/v1/compliance/checks \
  -F 'isms_p_item_id=1.1.4' \
  -F 'company_id=acme-corp' \
  -F 'evidence_metadata=[{"filename":"dns_events.json","evidence_type":"정책_시스템_설정","description":"eBPF DNS 이벤트"}]' \
  -F 'files=@dns_events.json'
```

### 4.2 허용 evidence_type

`정책_문서_존재`, `정책_문서_충실도`, `정책_시스템_설정`, `사용자_화면_강제화`, `변경주기_준수`, `임시_비밀번호_강제_변경`, `저장_형태`, `인증수단`

### 4.3 허용 파일 확장자

`.pdf`, `.png`, `.jpg`, `.jpeg`, `.webp`, `.json`, `.yaml`, `.yml`, `.csv`, `.txt`

---

## 5. 평가 파이프라인

### 5.1 processCheck 워커 흐름

```
1. 증적 파일 저장 (로컬 디스크)
2. 형식별 텍스트 추출
   - JSON → json.Unmarshal
   - PDF → pdftotext CLI
   - PNG/JPG → Tesseract OCR
   - CSV/TXT → 원문 그대로
3. extracted_text DB 저장
4. BGE-M3 임베딩 생성 (evidence_embedding + guideline_embedding)
5. 룰셋 로딩 → 룰별 증적 매칭 (evidence_type ↔ check_category)
6. 룰별 평가:
   - structured_match → evaluateStructured() + NormalizeRuleFixtureEvidence()
   - semantic_match → evaluateSemantic() (키워드 매칭)
   - regex_match → evaluateRegex()
   - aggregated_statistics → evaluateStatistics()
   - OCR 화면 → evaluateOCRKeywordMatch()
7. K8s 자원 추출기 (structured_match 위반 시) → 자원별 K8sSource 부여
8. 임베딩 2차 검증 → applyEmbeddingSecondPass()
9. 결과 DB 저장 (grc_checks, grc_rule_results, grc_violations)
```

### 5.2 임베딩 2차 검증

1차 평가(키워드/구조화 매칭) 후, DB에 저장된 evidence_embedding과 룰 지침 텍스트의 guideline_embedding을 코사인 유사도로 비교.
- 임계값: `GRC_EMBEDDING_MIN_COSINE` 환경변수 (기본 0.68)
- 1차가 "준수"인데 유사도 < 임계값이면 → "미준수"로 강등
- 임베딩 서버 미가동 시 graceful skip

### 5.3 K8s 자원 단위 위반 추출

`grc_resource_extractor.go`에 14개 룰의 추출기 등록:
- 1.1.4: R007(namespace 라벨), R011(DNS 이벤트), R012(Kyverno)
- 1.3.1: R007(정책 변경)
- 2.2.1: R002(개별 RoleBinding), R007(audit log)
- 2.2.2: R002(감사 이벤트), R003(겸직), R006(SoD), R008(self-merge)
- 2.2.5: R003(퇴직자 RB), R005(기존 권한), R009(orphaned 계정), R010(퇴직 후 활동)

각 위반에 `K8sSource{ClusterName, Namespace, ResourceKind, ResourceName, Container}` 포함.
DB `grc_violations` 테이블에 `k8s_cluster, k8s_namespace, k8s_kind, k8s_name, k8s_container` 컬럼으로 저장.

---

## 6. DB 스키마 (주요 테이블)

```sql
-- 005: 핵심 GRC 테이블
grc_checks (check_id, company_id, isms_p_item_id, status, verdict, summary_text, ...)
grc_rule_results (id, check_id, rule_id, verdict, violations→grc_violations, ...)
grc_violations (id, rule_result_id, field, expected, actual, description, severity,
                k8s_cluster, k8s_namespace, k8s_kind, k8s_name, k8s_container)
grc_evidence_files (id, check_id, filename, extracted_text,
                    guideline_text, evidence_embedding vector(1024), guideline_embedding vector(1024), ...)

-- 006: 임베딩 + 클라우드 환경
grc_cloud_environments (id, company_id, resource_type, raw_data, embedding vector(1024), ...)

-- 007: 증적 K8s 소스
grc_evidence_files.k8s_source (JSONB)

-- 008: 위반 K8s 소스
grc_violations.k8s_cluster/k8s_namespace/k8s_kind/k8s_name/k8s_container
```

마이그레이션: `migrations/001_init.up.sql` ~ `migrations/008_violation_k8s_source.up.sql`

---

## 7. 테스트

### 7.1 골든 테스트 (45 fixtures, 90 scenarios)

`ISMS-P_rule_testdata` 디렉토리에 `R-{item}-{nn}.json` 형식의 45개 fixture.
각 fixture에 `compliant` (PASS 기대) + `non_compliant` (FAIL 기대) 데이터 포함.

```bash
go test ./internal/service/ -run TestRuleFixturesGolden -count=1 -v
# 결과: 45 fixtures × 2 = 90 scenarios 전체 PASS
```

### 7.2 단위 테스트

- `grc_service_test.go` — 서비스 로직
- `grc_evidence_test.go` — 증적 매칭
- `grc_embedding_eval_test.go` — 임베딩 유사도
- `grc_ocr_parser_test.go` — OCR 텍스트 파싱
- `grc_k8s_attribution_test.go` — K8s 소스 매핑

---

## 8. 배포

### 8.1 Docker Compose

```bash
docker compose -f docker-compose.yml build backend
docker compose -f docker-compose.yml up -d
```

컨테이너 4개: `backend`, `postgres` (pgvector), `redis`, `embedding` (BGE-M3)

### 8.2 EC2 환경

- EC2: `ec2-user@3.38.106.127`
- PEM: `~/.ssh/vara-backend.pem`
- 프로젝트: `/home/ec2-user/vara-backend-isms`
- docker-compose 경로: `/home/ec2-user/vara-backend-isms/docker-compose.yml`

### 8.3 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `DATABASE_URL` | PostgreSQL 연결 문자열 | - |
| `REDIS_URL` | Redis 연결 문자열 | - |
| `EMBEDDING_SERVER_URL` | BGE-M3 서버 URL | - |
| `GRC_EMBEDDING_MIN_COSINE` | 임베딩 유사도 임계값 | 0.68 |
| `RULESET_DIR` | 룰셋 JSON 디렉토리 | `./rulesets` |

---

## 9. 알려진 이슈 및 남은 작업

### 9.1 R007 추출기 미연결
`1.1.4-R007`은 `semantic_match` 타입이라 `extractNsScopeViolations` 추출기가 호출되지 않음.
namespace 라벨 검사를 하려면 별도 `structured_match` 룰이 필요.

### 9.2 non-compliant API→DB 테스트 미완료
K8s k8s_source가 DB에 실제 저장되는 것을 API로 검증하는 테스트가 아직 미완.
`ck_2FEEFbQ92P` (R011 non-compliant DNS 데이터) 체크 결과 확인 필요.

### 9.3 향후 확장
- 나머지 ISMS-P 항목 룰셋 추가 (현재 10개 → 전체 60+개)
- Claude Vision API를 통한 VLM 기반 화면 캡처 평가
- cluster-reader agent 연동으로 자동 증적 수집
- 결과 PDF 리포트 export
- 대시보드 UI

---

## 10. 사용자 선호

- 캐주얼한 한국어 + 기술 영어 혼용
- 표/리스트로 시각적 구조화 선호
- 단순한 설계 선호 (가중치/우선순위 없이 1룰 실패 = 전체 미준수)
- Windows 환경에서 Git Bash fork 문제 빈발 → PowerShell 또는 EC2 직접 사용

---

**문서 끝.**
