# ISMS-P 2.5.4 비밀번호 관리 — 증적 샘플 패키지

GRC Compliance Check API의 입력 테스트용 가짜 증적 모음.
실제 회사 데이터 아니고 **PoC/테스트용 mock 데이터**.

---

## 폴더 구조

```
evidence/
├── compliant/       ← 모든 룰 PASS하는 증적 (verdict: 준수)
├── deficient/       ← 결함 포함된 증적 (verdict: 미준수)
├── evidence_metadata_compliant.json   ← API 요청 시 동봉할 메타데이터
└── evidence_metadata_deficient.json
```

---

## 룰별 증적 매핑

| Rule | 카테고리 | Compliant 파일 | Deficient 파일 |
|---|---|---|---|
| R001 | 정책_문서_존재 | `R001_R002_information_security_policy.pdf` | `R001_information_security_policy_NO_CHAPTER.pdf` |
| R002 | 정책_문서_충실도 | `R001_R002_information_security_policy.pdf` | `R002_information_security_policy_INCOMPLETE.pdf` |
| R003 | OS 패스워드 정책 | `R003_os_pam_policy.png` | `R003_os_pam_policy_DEFICIENT.png` |
| R004 | AD 패스워드 정책 | `R004_ad_password_policy.png` | `R004_ad_password_policy_DEFICIENT.png` |
| R005 | IAM 패스워드 정책 | `R005_iam_password_policy.png` + `.json` | `R005_iam_password_policy_DEFICIENT.png` + `.json` |
| R006 | DB 패스워드 정책 | `R006_db_password_policy.png` | `R006_db_password_policy_DEFICIENT.png` |
| R007 | WAS 패스워드 정책 | `R007_was_security.png` | `R007_was_security_DEFICIENT.png` |
| R008 | 사용자 화면 강제화 | `R008_signup_screen.png` | `R008_signup_screen_DEFICIENT.png` |
| R009 | 변경주기 준수 | `R009_account_password_age.csv` | `R009_account_password_age_DEFICIENT.csv` |
| R010 | 임시 비번 코드 | `R010_auth_module.txt` | `R010_auth_module_DEFICIENT.txt` |
| R011 | 첫 로그인 플로우 | `R011_first_login_flow.png` | `R011_first_login_flow_DEFICIENT.png` |
| R012 | 미변경자 목록 | `R012_temp_password_unchanged.csv` | `R012_temp_password_unchanged_DEFICIENT.csv` |
| R013 | DB 저장 형태 | `R013_db_password_samples.csv` | `R013_db_password_samples_DEFICIENT.csv` |
| R014 | MFA 설정 | `R014_mfa_policy.png` + `.json` | `R014_mfa_policy_DEFICIENT.png` + `.json` |
| R015 | 로그인 화면 | `R015_login_screen.png` + `_locked.png` | `R015_login_screen_DEFICIENT.png` + `_DEFICIENT2.png` |

---

## 사용 방법

### 1. 준수 케이스 테스트

```bash
curl -X POST https://api.vara.example/v1/compliance/check \
  -H "Authorization: Bearer $API_KEY" \
  -F "isms_p_item_id=2.5.4" \
  -F "company_id=demo_corp" \
  -F "auto_collect=false" \
  -F "evidence_metadata=@evidence_metadata_compliant.json" \
  $(for f in compliant/*; do echo -n "-F files=@$f "; done)
```

**기대 결과**: `verdict: "준수"`, `summary.failed: 0`

### 2. 미준수 케이스 테스트

```bash
curl -X POST https://api.vara.example/v1/compliance/check \
  -H "Authorization: Bearer $API_KEY" \
  -F "isms_p_item_id=2.5.4" \
  -F "company_id=demo_corp" \
  -F "evidence_metadata=@evidence_metadata_deficient.json" \
  $(for f in deficient/*; do echo -n "-F files=@$f "; done)
```

**기대 결과**: `verdict: "미준수"`, 모든 룰에 violation 발생

---

## 결함 시나리오 요약 (deficient 폴더)

- **R001**: 비밀번호 관련 챕터 자체가 없는 정책 문서
- **R002**: 챕터는 있으나 11개 필수 요소 중 8개 누락 (작성규칙 2개, 관리절차 6개)
- **R003 (OS)**: PASS_MAX_DAYS=99999, minlen=0, 복잡도 미설정
- **R004 (AD)**: 만료 없음, 복잡도 비활성화, 잠금 임계값 0
- **R005 (IAM)**: 6자, Require* 전부 false, 만료 없음
- **R006 (DB)**: 모든 항목 UNLIMITED, VERIFY_FUNCTION = NULL
- **R007 (WAS)**: 검증·잠금 비활성화, 기본 admin 계정 비번 미변경
- **R008 (UI)**: 짧은 비번도 통과, 정책 안내 없음
- **R009 (변경주기)**: 1/3이 200일 이상 미변경, 일부는 한번도 변경 안함
- **R010 (코드)**: MD5 해시, 임시 비번 강제 변경 로직 없음, 정보 노출
- **R011 (플로우)**: 임시 비번으로 대시보드 바로 진입
- **R012 (미변경자)**: 1000시간 이상 미변경자 다수
- **R013 (저장)**: MD5, SHA-1, 평문, Base64 혼재
- **R014 (MFA)**: 관리자 포함 대부분 MFA 미설정
- **R015 (로그인)**: 실패 시 "비밀번호가 틀렸습니다" 등 상세 메시지 노출

---

**생성일**: 2026-05-17
**대상 ISMS-P 항목**: 2.5.4 비밀번호 관리
**룰셋**: isms_p_2.5.4_ruleset.json (R001~R015, 총 15개)
