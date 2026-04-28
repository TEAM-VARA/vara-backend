# VARA Backend (Skeleton)

Go + Gin + PostgreSQL + Redis 기반의 단순 백엔드 스켈레톤.

## 구조

```
vara-backend/
├── cmd/server/main.go          # 진입점
├── internal/
│   ├── config/config.go        # 환경변수 로딩
│   ├── db/postgres.go          # PostgreSQL 연결
│   ├── db/redis.go             # Redis 연결
│   └── handler/handler.go      # HTTP 핸들러
├── migrations/001_init.sql     # DB 스키마
├── Dockerfile
├── docker-compose.yml
├── go.mod
└── .env.example
```

## 로컬 실행

```bash
cp .env.example .env
docker-compose up --build
```

기동되면:
- 백엔드: http://localhost:8080
- PostgreSQL: localhost:5432 (DBeaver로 접속)
- Redis: localhost:6379

## DBeaver 접속

- Host: `localhost`
- Port: `5432`
- Database: `vara`
- User: `vara`
- Password: `changeme`

`migrations/001_init.sql`은 PostgreSQL 컨테이너 첫 기동 시 자동 실행됩니다.

## 엔드포인트

| Method | Path | 설명 |
|---|---|---|
| GET | `/healthz` | DB 포함 헬스 체크 |
| POST | `/api/v1/agents/cluster-reader/pod-events` | Cluster Reader Agent |
| POST | `/api/v1/agents/ebpf/traffic` | eBPF Agent |
| POST | `/api/v1/agents/sbom` | SBOM 적재 |

각 핸들러 본문은 TODO 상태이며, 팀에서 채워가면 됩니다.

## 운영 배포 (EC2 + RDS + ElastiCache)

1. RDS PostgreSQL 생성, 같은 VPC private subnet에 배치
2. ElastiCache Redis 생성 (또는 EC2 내 Docker)
3. EC2에서 `docker build` 후 환경변수만 RDS/ElastiCache 엔드포인트로 바꿔서 실행
4. 보안그룹: Agent들의 SG에서만 8080 인바운드 허용

```bash
docker run -d -p 8080:8080 \
  -e POSTGRES_HOST=<RDS_ENDPOINT> \
  -e POSTGRES_PASSWORD=<from secrets manager> \
  -e POSTGRES_SSLMODE=require \
  -e REDIS_ADDR=<ELASTICACHE_ENDPOINT>:6379 \
  vara-backend
```
