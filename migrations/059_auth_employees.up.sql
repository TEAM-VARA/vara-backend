-- ============================================================================
-- VARA Auth — 직원 계정 + TOTP MFA
-- ============================================================================
--
-- 목적: 사번/비밀번호 로그인 + TOTP 2차 인증을 위한 사용자 저장소.
--   FE 흐름: login → (최초)mfa/setup(QR) → mfa/verify → 세션 JWT.
--
-- 설계 메모:
-- 1. password_hash 는 bcrypt(cost 10). 평문 저장 금지.
-- 2. mfa_secret 은 BASE32(TOTP). setup 단계에서 발급되며, 첫 verify 통과 전까지는
--    "미확정" 상태로 mfa_status='setup' 을 유지한다. 첫 verify 성공 시 'confirmed' 전환.
--    TODO(보안): at-rest 암호화(KMS/pgcrypto). 현재는 평문 BASE32 저장.
-- 3. last_totp_step 은 replay 방지용. 직전에 사용한 30초 step(unix/30)을 기록하고
--    같거나 이전 step 의 코드는 거부한다.
-- 4. role 은 RBAC 향후 연계용(operator|admin 등). 현재 라우트 보호엔 미적용.
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth_employees (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     TEXT        NOT NULL UNIQUE,          -- 사번 (로그인 ID)
    password_hash   TEXT        NOT NULL,                 -- bcrypt
    display_name    TEXT        NOT NULL DEFAULT '',
    role            TEXT        NOT NULL DEFAULT 'operator',
    mfa_secret      TEXT,                                 -- BASE32 (nullable: 미발급)
    mfa_status      TEXT        NOT NULL DEFAULT 'setup',  -- setup | confirmed
    last_totp_step  BIGINT      NOT NULL DEFAULT 0,        -- replay 방지 (직전 사용 step)
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 데모 시드: employee_id=admin / password=vara-demo-1234 / MFA 미등록(setup)
--   → FE 가 라이브 BE 로 "최초 QR 등록 → 6자리" 전체 흐름을 테스트할 수 있다.
--   운영 배포 전 반드시 비밀번호 변경 또는 시드 제거.
INSERT INTO auth_employees (employee_id, password_hash, display_name, role, mfa_status)
VALUES (
    'admin',
    '$2b$10$qsklypxEo5EY62If9WxyLeOJiwCJfFnnLXdGoz8jp3abCJ4yMSgDW',
    '데모 관리자',
    'admin',
    'setup'
)
ON CONFLICT (employee_id) DO NOTHING;
