# IAM 셋업 — vara-collector IRSA

EKS 클러스터의 vara-collector ServiceAccount 에 AWS API(현재는 RDS Describe)
권한을 부여하기 위한 IAM 리소스 템플릿이다.

## 한 번만 실행하는 셋업 단계

### 1. EKS 클러스터에 IAM OIDC provider 연결

```bash
eksctl utils associate-iam-oidc-provider \
  --cluster vara-test \
  --region ap-northeast-2 \
  --approve
```

연결 후 OIDC provider URL 을 확인:

```bash
aws eks describe-cluster --name vara-test --region ap-northeast-2 \
  --query "cluster.identity.oidc.issuer" --output text
# → https://oidc.eks.ap-northeast-2.amazonaws.com/id/XXXXXXXXXXXXXXXXXXXXX
```

`https://` 를 제거한 부분이 `OIDC_PROVIDER` 값이 된다.
예: `oidc.eks.ap-northeast-2.amazonaws.com/id/XXXXXXXXXXXXXXXXXXXXX`

### 2. trust policy 의 placeholder 치환

`collector-trust-policy.json` 에서 다음을 치환:

- `REPLACE_WITH_AWS_ACCOUNT_ID` → 본인 AWS account ID (예: 123456789012)
- `REPLACE_WITH_OIDC_PROVIDER` → 위에서 확인한 OIDC provider 경로

### 3. IAM Role 생성 + 정책 부착

```bash
aws iam create-role \
  --role-name vara-collector-role \
  --assume-role-policy-document file://collector-trust-policy.json

aws iam put-role-policy \
  --role-name vara-collector-role \
  --policy-name vara-collector-rds-describe \
  --policy-document file://collector-inline-policy.json
```

생성된 Role ARN 확인:

```bash
aws iam get-role --role-name vara-collector-role --query "Role.Arn" --output text
# → arn:aws:iam::123456789012:role/vara-collector-role
```

### 4. K8s manifest 의 placeholder 치환

`k8s/50-collector-rbac.yaml` 의 ServiceAccount annotation:

```yaml
eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/vara-collector-role
```

이후 `kubectl apply -f k8s/50-collector-rbac.yaml` 로 ServiceAccount 적용.

## 권한 확장이 필요한 경우

수집기 범위를 RDS 외 다른 AWS 리소스(ELB, Security Group 등)로 확장할 때
`collector-inline-policy.json` 의 Action 리스트에 추가하고
`aws iam put-role-policy` 로 갱신한다.
