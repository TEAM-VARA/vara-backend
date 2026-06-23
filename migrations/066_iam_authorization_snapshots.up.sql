-- migrations/065_iam_authorization_snapshots.up.sql
--
-- IAM 권한상승 탐지 — 소스 테이블(에이전트가 적재 → 탐지 모듈이 읽음).
-- 컬럼 컨벤션은 다른 AWS 스냅샷 테이블(aws_security_groups, aws_kms_keys,
-- aws_cloudtrail_trails ...)과 맞췄다: id BIGSERIAL PK, account_id, snapshot_at, received_at.
--
-- 모델: 멀티계정 / 계정별 최신 스냅샷만 유지.
--   - account_id 에 UNIQUE → 한 계정당 한 행.
--   - 에이전트는 매 스캔마다 ON CONFLICT (account_id) DO UPDATE 로 덮어쓴다.
--   - IAM 은 글로벌 서비스라 region 컬럼은 두지 않는다.
--
-- 데이터 형태: AWS iam:GetAccountAuthorizationDetails 응답을(정책 문서 URL 디코딩 후)
--   4개 리스트 그대로 JSONB 컬럼에 적재. 탐지 모듈이 이 구조를 그대로 파싱한다.

CREATE TABLE IF NOT EXISTS iam_authorization_snapshots (
    id                  BIGSERIAL   PRIMARY KEY,

    -- 12자리 AWS 계정 ID. 반드시 TEXT(선행 0 보존). UNIQUE → 계정당 1행, UPSERT 충돌 키.
    account_id          TEXT        NOT NULL UNIQUE,

    -- 사람이 읽을 별칭(iam:ListAccountAliases 또는 운영 측 매핑). 선택.
    account_alias       TEXT,

    -- ARN partition: 'aws' | 'aws-cn' | 'aws-us-gov'. 기본 'aws'.
    partition           TEXT        NOT NULL DEFAULT 'aws',

    -- 에이전트가 계정 권한을 캡처한 시각(UTC). 탐지 결과의 source_scanned_at 로 전파됨.
    snapshot_at         TIMESTAMPTZ NOT NULL,

    -- 적재한 에이전트 식별/버전(예: "iam-agent/1.4.2"). 디버깅·감사용. 선택.
    captured_by         TEXT,

    -- ---- GetAccountAuthorizationDetails 응답 4종(정책 문서는 URL 디코딩된 JSON) ----
    user_detail_list    JSONB       NOT NULL DEFAULT '[]'::jsonb,   -- UserDetailList[]
    role_detail_list    JSONB       NOT NULL DEFAULT '[]'::jsonb,   -- RoleDetailList[]
    group_detail_list   JSONB       NOT NULL DEFAULT '[]'::jsonb,   -- GroupDetailList[]
    policies            JSONB       NOT NULL DEFAULT '[]'::jsonb,   -- Policies[] (ManagedPolicyDetail)

    -- DB가 행을 받은 시각(서버 기준). 적재 지연 모니터링용.
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- 방어적 무결성 체크: 4개 컬럼은 JSON 배열이어야 함.
    CONSTRAINT chk_user_detail_list_is_array  CHECK (jsonb_typeof(user_detail_list)  = 'array'),
    CONSTRAINT chk_role_detail_list_is_array  CHECK (jsonb_typeof(role_detail_list)  = 'array'),
    CONSTRAINT chk_group_detail_list_is_array CHECK (jsonb_typeof(group_detail_list) = 'array'),
    CONSTRAINT chk_policies_is_array          CHECK (jsonb_typeof(policies)          = 'array')
);

COMMENT ON TABLE  iam_authorization_snapshots                   IS 'AWS 계정별 IAM 권한 구성 최신 스냅샷(GetAccountAuthorizationDetails raw). 계정당 1행, UPSERT.';
COMMENT ON COLUMN iam_authorization_snapshots.account_id        IS '12자리 AWS 계정 ID(TEXT, 선행 0 보존). UPSERT 충돌 키.';
COMMENT ON COLUMN iam_authorization_snapshots.snapshot_at       IS '에이전트가 권한을 캡처한 시각(UTC).';
COMMENT ON COLUMN iam_authorization_snapshots.user_detail_list  IS 'GetAccountAuthorizationDetails 의 UserDetailList. 정책 문서는 URL 디코딩된 JSON.';
COMMENT ON COLUMN iam_authorization_snapshots.role_detail_list  IS 'RoleDetailList. AssumeRolePolicyDocument 포함, URL 디코딩된 JSON.';
COMMENT ON COLUMN iam_authorization_snapshots.group_detail_list IS 'GroupDetailList.';
COMMENT ON COLUMN iam_authorization_snapshots.policies          IS 'Policies(ManagedPolicyDetail). 관리형 정책 ARN→문서 해석에 필요(AWS관리형 포함).';

CREATE INDEX IF NOT EXISTS idx_iam_snapshots_snapshot_at ON iam_authorization_snapshots (snapshot_at DESC);
