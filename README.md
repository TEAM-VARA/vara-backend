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
