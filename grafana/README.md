# VARA Grafana 임베드 셋업

VARA 홈 화면 임베드용 Grafana. **VARA 플랫폼 쪽(RDS 있는 EC2)** 에 배포. (train-ticket 아님)
`docker compose up` 하면 RDS 데이터소스 + 홈 대시보드(4종 패널)가 자동 프로비저닝된다.

## 구성
```
grafana/
├── docker-compose.grafana.yml        # grafana-oss + 임베드 env + provisioning 마운트
├── .env.example                      # RDS 접속·관리자 비번 (복사해서 .env)
├── readonly_user.sql                 # RDS 읽기전용 계정 생성 (RDS에 1회 실행)
└── provisioning/
    ├── datasources/vara-rds.yaml     # PostgreSQL(RDS) 데이터소스 (uid: vara-rds)
    └── dashboards/
        ├── provider.yaml
        └── json/vara-home.json       # 홈 대시보드 (uid: vara-home)
```

## 실행 순서 (우선순위대로)

### 1) RDS 읽기전용 계정 (권장)
```bash
# RDS에 관리자로 1회 (readonly_user.sql 안의 비밀번호 먼저 수정)
psql "host=<RDS-endpoint> dbname=vara user=<admin> sslmode=require" -f readonly_user.sql
```

### 2) Grafana 띄우기 + RDS 붙이기
```bash
cp .env.example .env        # RDS_HOST/DB/USER/PASSWORD, GRAFANA_ADMIN_PASSWORD 채우기
docker compose -f docker-compose.grafana.yml --env-file .env up -d
# 확인: http://<EC2-IP>:3000  (admin / .env의 비번)  → Dashboards > VARA Home
# 데이터소스 연결 확인: Connections > Data sources > VARA-RDS > Save & test
```

### 3) 임베드 허용 (이미 docker-compose env로 설정됨)
- `GF_SECURITY_ALLOW_EMBEDDING=true`, 익명 Viewer 활성 — FE iframe 가능.
- **리버스 프록시(nginx)를 앞에 둘 경우** X-Frame-Options 제거 + FE 도메인 허용:
```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_hide_header X-Frame-Options;                 # Grafana가 안 보내지만 프록시가 추가 시 제거
    add_header Content-Security-Policy "frame-ancestors 'self' https://<FE-도메인>";
}
```
> 같은 도메인/포트면 프록시 없이 익명 Viewer만으로 임베드된다. 교차 도메인이면 위 CSP + `GF_SERVER_ROOT_URL`을 외부 URL로.

## FE 에 넘겨줄 값 (임베드 계약)

| 항목 | 값 |
|---|---|
| Grafana base URL | `http://<EC2-IP>:3000` (또는 프록시 도메인) |
| 대시보드 UID | `vara-home` |
| 대시보드 slug | `vara-home` |

패널별 `panelId`:

| panelId | 패널 | 데이터 |
|---|---|---|
| 1 | Risk 등급 분포 | `final_scores`(최신 snapshot) risk_level 카운트 |
| 2 | ISMS-P 준수 현황 | `grc_cluster_compliance_results`(최신) 준수/미준수/검토 |
| 3 | 권한(RBAC) 위험 | `rbac_sa_reports`(admin 도달/전체) + `rbac_escalation_paths` |
| 4 | CVE 심각도별 | `cves` severity별 distinct CVE 수 |
| 5 | eBPF 통신 추이 | `ebpf_network_flows` timestamp 시계열 |

FE 임베드 URL 형식:
```
http://<grafana-host>/d-solo/vara-home/vara-home?panelId=1&theme=dark&kiosk&var-cluster=vara-eks-test
```
- `theme=dark|light` 토글 지원. `var-cluster=`로 클러스터 변경 가능.
- 전체 대시보드를 통째로 임베드하려면 `/d/vara-home/vara-home?kiosk&theme=dark`.

## 패널 SQL 메모 (스키마 기준)
- 실제 스키마에 맞춰 작성됨(요청서의 `compliance_isms_p_mappings` 대신 **존재하는 `grc_cluster_compliance_results`** 사용).
- **Risk 등급**: `final_scores.risk_level` 값 그대로 GROUP BY(런타임 저장값: safe/caution/warning/emergency). 점수 기준 재분류가 필요하면 `final_score` CASE로 교체.
- **RBAC(패널 3)**: `rbac_sa_reports`(reaches_cluster_admin)·`rbac_escalation_paths` 사용. **컬럼·해석은 이준혁과 최종 확인** 권장.
- **ISMS-P(패널 2)**: GRC 결과 테이블이 이예은 영역 — 컬럼명 변동 시 SQL만 조정.
- `cves`에는 cluster_name이 없어 클러스터 필터 없이 전체 집계(이미지 단위).

## 추후
- 패널 추가(추이/Top 위험 Pod 등)는 `vara-home.json` panels 배열에 append 후 컨테이너 재시작(provisioning 자동 반영).
- 읽기전용 계정 권장(RDS 보호). 패널은 우선 5개.
