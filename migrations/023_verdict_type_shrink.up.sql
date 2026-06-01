-- ============================================================================
-- VARA Backend - Migration 023: verdict_type 3종으로 축소
-- 'additional_evidence' 제거 → F-2.1.3-K8S-01, F-2.8.3-K8S-01 needs_review 재지정
-- ============================================================================

-- 1) 두 Finding을 needs_review로 변경 (제약 변경 전에 먼저 데이터 업데이트)
UPDATE compliance_findings
SET verdict_type = 'needs_review', updated_at = NOW()
WHERE finding_id IN ('F-2.1.3-K8S-01', 'F-2.8.3-K8S-01')
  AND verdict_type = 'additional_evidence';

-- 2) 혹시 남은 additional_evidence 값 모두 needs_review로 치환 (안전)
UPDATE compliance_findings
SET verdict_type = 'needs_review', updated_at = NOW()
WHERE verdict_type = 'additional_evidence';

-- 3) 기존 CHECK 제약 제거
ALTER TABLE compliance_findings
    DROP CONSTRAINT IF EXISTS compliance_findings_verdict_type_check;

-- 4) 새 3종 CHECK 제약 추가
ALTER TABLE compliance_findings
    ADD CONSTRAINT compliance_findings_verdict_type_check
        CHECK (verdict_type IN ('compliant_indicator', 'potential_finding', 'needs_review'));
