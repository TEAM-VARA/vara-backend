-- 시스템 pod(tetragon/ebs-csi-node) 엣지 및 shares_image 전체 제거
-- 배경: 그래프 노이즈 감소 (edges_repo.go의 생성 로직도 동일하게 제외 처리됨)
--  - shares_image: 공통 사이드카 이미지 공유로 N² 폭발 (CVE 허브 재설계 전까지 비활성)
--  - tetragon/ebs-csi-node: 시스템 데몬셋, 대시보드 표시 제외
DELETE FROM edges
WHERE edge_type = 'shares_image'
   OR source_name LIKE 'tetragon%' OR target_name LIKE 'tetragon%'
   OR source_name LIKE 'ebs-csi-node%' OR target_name LIKE 'ebs-csi-node%';