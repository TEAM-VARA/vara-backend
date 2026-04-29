# VARA Compliance — Operations Guide

AWS EKS 위에 VARA compliance 스택을 0부터 띄우고, 동작을 검증하는 절차.

---

## 0. 전체 그림

```
[VPC vara-test-vpc]
   ├─ [EKS cluster vara-test]            ← Step 1
   │   └─ namespace vara-compliance
   │       ├─ Deployment vara-api          (Go gin)
   │       ├─ Deployment vara-embedding    (Python BGE-M3)
   │       ├─ Job vara-seed                (1회 ISMS-P 통제 등록)
   │       └─ CronJob vara-collector       (6시간 주기 스캔)
   │
   ├─ [RDS PostgreSQL]                    ← Step 0.3
   │   └─ DB vara
   │       ├─ vara-backend 테이블들
   │       └─ compliance_* 테이블들 (우리)
   │
   └─ [ECR repos × 4]                     ← Step 1
       ├─ vara-api
       ├─ vara-embedding-server
       ├─ vara-seed
       └─ vara-collector
```

데이터 흐름:

```
collector(K8s read + AWS RDS) → vara-api/assets,vulnerabilities,exposures
   → vara-api/evidence/generate → embedding-server(BGE-M3) → RDS pgvector
seed → vara-api/isms-p/controls (BGE-M3 임베딩) → RDS pgvector
seed → vara-api/isms-p/mappings/run → cosine 유사도 검색 → 룰 엔진 판정
```

---

## 1. 사전 준비

### 1.1 IAM/AWS CLI 로그인

```bash
aws configure   # Access Key/Region(ap-northeast-2)/Output(json)
aws sts get-caller-identity   # 본인 ARN 확인
```

이후 명령에서 사용할 변수:

```bash
export AWS_REGION=ap-northeast-2
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR_REGISTRY=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
export VPC_ID=vpc-063a3212a022aad46     # vara-test-vpc
export CLUSTER_NAME=vara-test
```

### 1.2 EKS 클러스터 생성 (없을 때만)

VPC 가 이미 있으므로 `--vpc-private-subnets` 대신 기존 public 서브넷 ID 를 직접 지정.

```bash
# 서브넷 ID 확인
aws ec2 describe-subnets --filters "Name=vpc-id,Values=${VPC_ID}" \
  --query "Subnets[].{ID:SubnetId,AZ:AvailabilityZone,Name:Tags[?Key=='Name']|[0].Value}" \
  --output table

# eksctl 로 생성 (예시 — 본인 환경 서브넷 ID 로 교체)
eksctl create cluster \
  --name ${CLUSTER_NAME} \
  --region ${AWS_REGION} \
  --version 1.30 \
  --vpc-public-subnets subnet-AAAA,subnet-BBBB \
  --node-type t3.large \
  --nodes 2 --nodes-min 2 --nodes-max 4 \
  --managed
```

생성 시간: 약 15~20분.

### 1.3 RDS 확인 / 생성

이미 vara-backend 가 쓰는 RDS 가 있다고 가정. 두 가지 확인:

```bash
# 엔진 버전 (pgvector 는 PostgreSQL 15.3+ 필요)
aws rds describe-db-instances \
  --query "DBInstances[].{ID:DBInstanceIdentifier,Engine:Engine,Ver:EngineVersion,Endpoint:Endpoint.Address}"

# pgvector extension + 우리 스키마 적용
psql "host=<RDS_ENDPOINT> port=5432 user=vara dbname=vara sslmode=require" \
  -c "CREATE EXTENSION IF NOT EXISTS vector;" \
  -f schema.sql
```

`schema.sql` 은 모든 테이블에 `compliance_` prefix 가 붙어 있어 vara-backend 와 충돌하지 않는다.

### 1.4 ECR 리포 4개 생성

```bash
for repo in vara-api vara-embedding-server vara-seed vara-collector; do
  aws ecr create-repository --repository-name ${repo} --region ${AWS_REGION}
done

# 도커 로그인
aws ecr get-login-password --region ${AWS_REGION} \
  | docker login --username AWS --password-stdin ${ECR_REGISTRY}
```

### 1.5 IRSA 셋업 (collector AWS 권한)

[iam/README.md](iam/README.md) 의 4단계를 실행.

요약:
```bash
eksctl utils associate-iam-oidc-provider --cluster ${CLUSTER_NAME} --approve

# trust policy 의 placeholder 치환 후
aws iam create-role --role-name vara-collector-role \
  --assume-role-policy-document file://iam/collector-trust-policy.json
aws iam put-role-policy --role-name vara-collector-role \
  --policy-name rds-describe --policy-document file://iam/collector-inline-policy.json

aws iam get-role --role-name vara-collector-role --query "Role.Arn" --output text
# 출력된 ARN 을 k8s/50-collector-rbac.yaml 의 REPLACE_WITH_IAM_ROLE_ARN 에 넣기
```

---

## 2. 이미지 빌드 + 푸시

리포 루트(`VARA/`)에서 실행:

```bash
TAG=v0.1.0

# 1) vara-api
docker build -t ${ECR_REGISTRY}/vara-api:${TAG} .
docker push ${ECR_REGISTRY}/vara-api:${TAG}

# 2) embedding-server (build context 는 VARA/ 루트, Dockerfile 위치 지정)
docker build -t ${ECR_REGISTRY}/vara-embedding-server:${TAG} \
  -f embedding-server/Dockerfile .
docker push ${ECR_REGISTRY}/vara-embedding-server:${TAG}

# 3) seed
docker build -t ${ECR_REGISTRY}/vara-seed:${TAG} \
  -f seed/Dockerfile .
docker push ${ECR_REGISTRY}/vara-seed:${TAG}

# 4) collector
docker build -t ${ECR_REGISTRY}/vara-collector:${TAG} \
  -f collector/Dockerfile .
docker push ${ECR_REGISTRY}/vara-collector:${TAG}
```

**주의**: embedding-server 이미지가 가장 큼 (약 1.5GB) — 첫 푸시 5~10분 걸림.

---

## 3. K8s 매니페스트 적용

### 3.1 placeholder 치환

`k8s/` 디렉토리의 다음 placeholder 들을 본인 환경 값으로 교체:

| 파일 | placeholder | 치환 값 |
|---|---|---|
| `10-secret.yaml` | `REPLACE_WITH_RDS_ENDPOINT` | RDS 엔드포인트 |
| `10-secret.yaml` | `REPLACE_WITH_RDS_PASSWORD` | RDS 비밀번호 |
| `20-embedding-server.yaml` | `REPLACE_WITH_REGISTRY` | `${ECR_REGISTRY}` |
| `30-vara-api.yaml` | `REPLACE_WITH_REGISTRY` | `${ECR_REGISTRY}` |
| `40-seed-job.yaml` | `REPLACE_WITH_REGISTRY` | `${ECR_REGISTRY}` |
| `50-collector-rbac.yaml` | `REPLACE_WITH_IAM_ROLE_ARN` | Step 1.5 의 ARN |
| `51-collector-cronjob.yaml` | `REPLACE_WITH_REGISTRY` | `${ECR_REGISTRY}` |

일괄 치환 예 (sed):

```bash
cd k8s/
sed -i "s|REPLACE_WITH_REGISTRY|${ECR_REGISTRY}|g" *.yaml
# RDS 정보는 명령행 보안상 직접 vi 로 수정 권장
# 또는 stringData 부분만 빼고 kubectl create secret 으로 따로 만드는 게 더 안전
```

### 3.2 적용 순서

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/10-secret.yaml
kubectl apply -f k8s/11-configmap.yaml
kubectl apply -f k8s/20-embedding-server.yaml   # 모델 다운로드 약 5분
kubectl apply -f k8s/30-vara-api.yaml
kubectl apply -f k8s/50-collector-rbac.yaml
kubectl apply -f k8s/51-collector-cronjob.yaml

# embedding-server / vara-api 가 Ready 가 된 뒤에 seed Job 실행
kubectl -n vara-compliance wait --for=condition=available deployment/vara-embedding-server --timeout=10m
kubectl -n vara-compliance wait --for=condition=available deployment/vara-api --timeout=5m
kubectl apply -f k8s/40-seed-job.yaml
```

또는 한 번에:
```bash
kubectl apply -f k8s/
```

(이 경우 seed Job 이 vara-api 보다 먼저 시작될 수 있는데, seed/main.go 의 `waitForAPI` 가
90초 동안 재시도하므로 보통 통과한다)

---

## 4. 동작 검증

### 4.1 모든 Pod 가 Running 인지

```bash
kubectl -n vara-compliance get pods -w
```

기대:
- `vara-api-xxx` Running 1/1
- `vara-embedding-server-xxx` Running 1/1
- `vara-seed-xxx` Completed
- collector 는 CronJob 이라 다음 실행 전까진 Pod 없음

### 4.2 vara-api 헬스체크

```bash
kubectl -n vara-compliance port-forward svc/vara-api 8080:8080 &
curl http://localhost:8080/healthz
# {"status":"ok"}
curl http://localhost:8080/readyz
# {"status":"ready"}
```

### 4.3 ISMS-P 통제항목 25개 등록 확인

```bash
curl -s http://localhost:8080/api/v1/isms-p/controls | jq '.data.items | length'
# 25
curl -s http://localhost:8080/api/v1/isms-p/controls | jq '.data.items[] | {id:.control_id, title:.title}'
```

### 4.4 collector 수동 실행 (CronJob 안 기다리고)

```bash
kubectl -n vara-compliance create job vara-collector-now --from=cronjob/vara-collector

# 로그 추적
kubectl -n vara-compliance logs -f job/vara-collector-now
```

기대 로그 패턴:
```
[phase1] discovered 42 pods
[phase2] discovered 5 k8s exposures
[phase3] discovered 1 RDS instances (1 public)
[phase4] scanned 38 / 42 pods
[phase5] evidence generated for 43 / 43 assets
collector run completed
```

### 4.5 결과 데이터 확인

```bash
# 자산 목록
curl -s http://localhost:8080/api/v1/assets | jq '.data.items | length'

# CVE 발견 건수 (특정 asset_id)
curl -s "http://localhost:8080/api/v1/assets/pod%3A%2F%2Fvara-test%2Fdefault%2Fweb-1/vulnerabilities" \
  | jq '.data.vulnerabilities | length'

# 노출도 E4 (외부 노출) 만
curl -s "http://localhost:8080/api/v1/exposures?level=E4" | jq '.data.items'

# 매핑 결과 — NON_COMPLIANT 우선
curl -s http://localhost:8080/api/v1/isms-p/mappings | jq '.data.items[] | select(.status=="NON_COMPLIANT")'
```

### 4.6 특정 ISMS-P 항목의 매핑 재실행

```bash
curl -X POST http://localhost:8080/api/v1/isms-p/mappings/run \
  -H "Content-Type: application/json" \
  -d '{
    "control_id": "2.10.8",
    "top_k": 10,
    "min_similarity": 0.5
  }' | jq
```

기대: status, risk_level, summary, evidence (관련 CVE/노출/자산 evidence) 까지 반환.

---

## 5. 트러블슈팅

### embedding-server Pod 가 5분 넘게 Pending/NotReady

- 모델 다운로드(BGE-M3, 약 2.3GB) 첫 부팅 시 5분 정도 정상.
- `kubectl logs` 에 `Downloading` 메시지가 보이면 기다리면 됨.
- 5GB EmptyDir 한계로 Pod 내릴 때마다 재다운로드 됨 → 영구 캐시 원하면 PVC 로 전환.

### ImagePullBackOff

- 노드의 IAM 인스턴스 프로파일에 ECR pull 권한이 있는지 확인.
- `eksctl create cluster` 가 만든 nodegroup 에는 기본 포함됨.
- 확인: `kubectl describe pod <pod>` → Events 에 ECR 권한 에러 표시.

### vara-api CrashLoopBackOff

- 거의 RDS 연결 실패. `kubectl logs` 첫 줄 확인.
- RDS 보안그룹이 EKS 노드 보안그룹의 5432 inbound 를 허용하는지.
- Secret 의 POSTGRES_HOST / PASSWORD 정확한지.

### collector Job 가 RDS describe 실패

- IRSA 가 안 붙은 것. ServiceAccount 의 annotation 과 IAM Role 의 trust policy 가 정확히 같은
  OIDC provider 와 SA 이름을 가리켜야 함.
- 확인: `kubectl -n vara-compliance describe sa vara-collector` 에 annotation 보이는지.
- `aws sts assume-role-with-web-identity` 가 collector Pod 환경변수로 자동 주입되는지:
  `kubectl exec ... -- env | grep AWS_`

### 매핑 결과가 다 COMPLIANT 로 나옴

- evidence_documents 가 비어있거나, ISMS-P 통제 임베딩이 안 만들어진 것.
- 확인: `curl /api/v1/evidence | jq '.data.items | length'`
- 0이면 collector 가 evidence 생성 단계에서 실패한 것 — collector logs 에서 [phase5] 확인.

---

## 6. 운영 메모

### CronJob 스케줄 변경

`k8s/51-collector-cronjob.yaml` 의 `schedule` 수정 후 `kubectl apply`. 6시간 → 1시간 등.

### 데이터 누적 문제

현재 `compliance_vulnerabilities` / `compliance_exposures` / `compliance_evidence_documents` 는
collector 가 매번 INSERT 하므로 row 가 누적된다. 옵션:

- (a) 각 테이블에 UNIQUE constraint 추가 + ON CONFLICT 처리
- (b) collector가 POST 전에 해당 자산의 기존 row DELETE
- (c) 매핑 결과만 보면 되니 그냥 두고 매핑 시 최신 evidence 만 사용

운영 단계에서 결정 필요. 데모 단계에선 일단 두자.

### 비용 견적 (대략)

- EKS control plane: $0.10/h ≈ $73/월
- t3.large 노드 × 2: $0.10/h × 2 ≈ $146/월
- RDS db.t3.medium: $70~/월
- ECR storage 50GB: 무료 한도 내
- BGE-M3 emptyDir 5GB: 무료
→ 데모는 한 달 $300 안쪽
