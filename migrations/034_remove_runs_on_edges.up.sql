-- runs_on 엣지 제거 (host layer 재설계)
-- 사유: 모든 pod이 1개씩 가져 엣지 과다(171), 위험 신호 아님
--       탈출 위험은 escape_path(privileged/hostNetwork/hostPID/hostPath)가 표현
DELETE FROM edges WHERE layer = 'host' AND edge_type = 'runs_on';