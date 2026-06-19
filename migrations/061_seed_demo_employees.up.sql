-- ============================================================================
-- 테스트용 데모 직원 시드 (admin1~admin4)
-- ============================================================================
-- 목적: 팀원들이 각자 로그인/MFA 등록을 테스트할 수 있도록 4개 계정 생성.
--   - 비밀번호: 1234 (bcrypt cost 10) — 테스트 전용.
--   - mfa_status='setup' → 각자 본인 인증앱(Google Authenticator 등)으로 등록.
--   ⚠ 테스트 종료 후 제거 또는 비밀번호 변경 필요 (운영 배포 금지).
-- ============================================================================

INSERT INTO auth_employees (employee_id, password_hash, display_name, role, mfa_status)
VALUES
    ('admin1', '$2b$10$3Bo4/jJgJ0cEN9M9jhblReAe.n3raI8VEQ9wGrjg32Vb83lA5L5He', '데모 admin1', 'operator', 'setup'),
    ('admin2', '$2b$10$3Bo4/jJgJ0cEN9M9jhblReAe.n3raI8VEQ9wGrjg32Vb83lA5L5He', '데모 admin2', 'operator', 'setup'),
    ('admin3', '$2b$10$3Bo4/jJgJ0cEN9M9jhblReAe.n3raI8VEQ9wGrjg32Vb83lA5L5He', '데모 admin3', 'operator', 'setup'),
    ('admin4', '$2b$10$3Bo4/jJgJ0cEN9M9jhblReAe.n3raI8VEQ9wGrjg32Vb83lA5L5He', '데모 admin4', 'operator', 'setup')
ON CONFLICT (employee_id) DO NOTHING;
