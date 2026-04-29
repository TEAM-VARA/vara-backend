# VARA Compliance — Cloud Compliance RAG API

AWS EKS 위에서 자산(Pod/RDS), 취약점(CVE), 외부 노출도 정보를 수집해
ISMS-P 통제항목과 pgvector + BGE-M3 임베딩 기반 유사도로 매핑하는 컴플라이언스 시스템.

---

## 1. 핵심 흐름

```
[Cloud/K8s 자산]                       [수집기 CronJob]
  Pod / Service / Ingress      ──→     k8s API + AWS RDS Describe
  RDS PubliclyAccessible / SSE          ↓
                                 [Trivy image scan]
                                        ↓
[CVE / 노출 / 자산 자체 속성]    ──→   /api/v1/evidence/generate
                                        ↓
                              [Evidence 문장화 (한국어)]
                                        ↓
                                  [BGE-M3 1024차원 임베딩]
                                        ↓
                                  [PostgreSQL + pgvector]
                                  compliance_evidence_documents.embedding
                                  compliance_isms_p_controls.embedding
                                        ↓
                              [cosine 유사도 Top-K 검색]
                                        ↓
                              [룰 엔진: 유사도 + CVE 심각도 + 노출도]
                                        ↓
                          COMPLIANT / NEEDS_REVIEW / NON_COMPLIANT
```

---

## 2. 디렉토리 구조

```
VARA/
├── main.go                  # vara-api: Go gin 기반 REST API
├── schema.sql               # PostgreSQL + pgvector 스키마 (compliance_ prefix)
├── Dockerfile               # vara-api 이미지
│
├── embedding_server.py      # BGE-M3 FastAPI 서버
├── embedding-server/
│   ├── Dockerfile
│   └── requirements.txt
│
├── seed/                    # ISMS-P 통제 25개 일괄 등록 + 매핑 실행
│   ├── main.go
│   ├── isms_p_controls.json
│   └── Dockerfile
│
├── collector/               # K8s + AWS RDS 수집기
│   ├── main.go              # 오케스트레이션
│   ├── k8s.go               # Pod/Service/Ingress 발견
│   ├── aws.go               # RDS Describe
│   ├── trivy.go             # 이미지 취약점 스캔
│   ├── api.go               # vara-api HTTP 클라이언트
│   └── Dockerfile
│
├── k8s/                     # K8s 매니페스트
│   ├── 00-namespace.yaml
│   ├── 10-secret.yaml       # RDS 자격증명 (placeholder)
│   ├── 11-configmap.yaml
│   ├── 20-embedding-server.yaml
│   ├── 30-vara-api.yaml
│   ├── 40-seed-job.yaml
│   ├── 50-collector-rbac.yaml
│   └── 51-collector-cronjob.yaml
│
├── iam/                     # IRSA 셋업 (collector AWS 권한)
│   ├── collector-trust-policy.json
│   ├── collector-inline-policy.json
│   └── README.md
│
├── README.md                # 본 문서
└── OPERATIONS.md            # 배포/검증 런북 (팀원 인수인계용)
```

---

## 3. 사용 시나리오

### 3.1 단일 자산 → 단일 ISMS-P 항목 매핑

```bash
# 1) 자산 등록
curl -X POST localhost:8080/api/v1/assets \
  -d '{"asset_id":"pod://prod/default/web-1","asset_type":"pod","name":"web-1",
       "image":"nginx:1.18","service_account":"default",
       "metadata":{"privileged":true,"host_network":false}}'

# 2) Evidence 생성 (CVE/노출/자산 속성 → 한국어 문장 + 임베딩)
curl -X POST localhost:8080/api/v1/evidence/generate \
  -d '{"asset_id":"pod://prod/default/web-1"}'

# 3) ISMS-P 2.5.5(특수 권한) 와 매핑
curl -X POST localhost:8080/api/v1/isms-p/mappings/run \
  -d '{"control_id":"2.5.5","top_k":10,"min_similarity":0.5}'
# → status: NON_COMPLIANT, summary: privileged=true Pod 가 검색됨
```

### 3.2 클러스터 전체 자동 스캔

K8s CronJob `vara-collector` 가 매 6시간마다:
1. 모든 Pod 발견 → 자산 등록
2. LoadBalancer/Ingress → 외부 노출 등록
3. AWS RDS PubliclyAccessible → 노출 등록
4. Pod 이미지마다 Trivy 스캔 → CVE 등록
5. 각 자산에 대해 evidence 생성 (자산 속성 + CVE + 노출)

---

## 4. 빠른 시작

### 로컬 (개발용)

```bash
# 1) PostgreSQL + pgvector 띄우기
docker run -d --name pg16 -p 5432:5432 \
  -e POSTGRES_PASSWORD=postgres \
  pgvector/pgvector:pg16

# 2) 스키마 적용
psql "postgres://postgres:postgres@localhost/postgres" -c "CREATE DATABASE vara;"
psql "postgres://postgres:postgres@localhost/vara" -f schema.sql

# 3) 임베딩 서버
cd embedding-server
pip install -r requirements.txt
uvicorn embedding_server:app --port 9000 &

# 4) vara-api
cd ..
POSTGRES_HOST=localhost POSTGRES_PASSWORD=postgres \
POSTGRES_DB=vara POSTGRES_SSLMODE=disable \
go run .
```

### AWS EKS 배포

→ [OPERATIONS.md](./OPERATIONS.md) 참고. 0부터 따라하면 약 1시간.

---

## 5. API 엔드포인트

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/healthz` | liveness |
| GET | `/readyz` | DB ping 까지 확인 |
| POST | `/api/v1/assets` | 자산 등록/갱신 |
| GET | `/api/v1/assets` | 자산 목록 |
| GET | `/api/v1/assets/:id` | 자산 상세 |
| POST | `/api/v1/vulnerabilities` | CVE 일괄 등록 |
| GET | `/api/v1/assets/:id/vulnerabilities` | 자산별 CVE |
| POST | `/api/v1/exposures` | 노출 등록 |
| GET | `/api/v1/exposures?level=E4` | 노출 조회 |
| POST | `/api/v1/isms-p/controls` | ISMS-P 통제 등록 (임베딩 자동 생성) |
| GET | `/api/v1/isms-p/controls` | 통제 목록 |
| POST | `/api/v1/evidence/generate` | CVE/노출/자산 → 문장형 Evidence + 임베딩 |
| POST | `/api/v1/vector-search/isms-p` | 통제 기준 Evidence 유사도 검색 |
| POST | `/api/v1/isms-p/mappings/run` | 매핑 실행 (검색 + 룰 엔진) |
| GET | `/api/v1/isms-p/mappings` | 매핑 결과 목록 |

---

## 6. 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `SERVER_PORT` | `8080` | vara-api listen 포트 |
| `POSTGRES_HOST/PORT/USER/PASSWORD/DB/SSLMODE` | `localhost/5432/vara/<empty>/vara/disable` | RDS/PG 접속 |
| `DATABASE_URL` | (선택) | URL 형식이 더 편할 때 fallback |
| `EMBEDDING_SERVER_URL` | `http://localhost:9000/embed` | BGE-M3 서버 endpoint |

---

## 7. 팀원이 이 코드 받아서 배포할 때

```bash
# 1) 클론
git clone https://github.com/TEAM-VARA/vara-backend.git
cd vara-backend
git checkout dev

# 2) AWS prereq + 이미지 빌드 + K8s apply
#    → OPERATIONS.md 의 1~3단계 그대로 따라하면 됨

# 3) 동작 확인
#    → OPERATIONS.md 의 4단계 (curl + kubectl 명령들)
```

자세한 절차는 [OPERATIONS.md](./OPERATIONS.md).
