package scoring

import "fmt"

// HopEdge — blast_edges 한 행의 시나리오용 읽기 뷰 (채널 확률 3개 전부).
// win_channel(승자)만이 아니라 p_host/p_rbac/p_net을 다 들고 있어, 한 엣지에 여러 채널이
// 살아 있으면(예: host로 win했지만 rbac도 가능) 채널별로 모두 풀어줄 수 있다.
type HopEdge struct {
	SourceUID, TargetUID   string
	SourceName, TargetName string
	PHost, PRBAC, PNet     float64
	WinChannel             string // host | rbac | network (= max 채널, reason의 주인)
	Reason                 string // 승자 채널의 근거 (비승자 채널은 근거 미저장 → 빈 값)
}

// HopChannel — 한 엣지(src→dst)의 한 채널 시나리오.
type HopChannel struct {
	Channel  string  `json:"channel"` // network | rbac | host
	Tactic   string  `json:"tactic"`
	Prob     float64 `json:"prob"`
	Scenario string  `json:"scenario"`
	Reason   string  `json:"reason,omitempty"` // 승자 채널이면 blast reason, 아니면 빈 값
}

// HopScenario — 이 pod에서 나가는 엣지 1개(src→dst)의 시나리오. 살아있는 채널을 모두 담는다.
//
// origin/BFS 없음 — "이 pod이 바로 옆 pod으로 어떻게 옮겨가나"의 1홉 뷰다. 프론트는 여러 pod의
// 응답을 source_uid→target_uid로 이어붙여 전체 전파 그래프를 구성한다.
type HopScenario struct {
	SourceUID  string       `json:"source_uid"`
	SourceName string       `json:"source_name"`
	TargetUID  string       `json:"target_uid"`
	TargetName string       `json:"target_name"`
	Channels   []HopChannel `json:"channels"`
}

// BuildOutgoingScenarios — 이 pod의 나가는 엣지(1홉) 각각을 채널별 시나리오로 렌더한다.
// 입력은 호출부에서 p_edge desc 정렬되어 들어오므로 강한 엣지가 앞에 온다.
func BuildOutgoingScenarios(edges []HopEdge) []HopScenario {
	out := make([]HopScenario, 0, len(edges))
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue
		}
		if hs := edgeScenario(e); len(hs.Channels) > 0 {
			out = append(out, hs)
		}
	}
	return out
}

// edgeScenario — 엣지 1개 → 살아있는 채널별 시나리오. reason은 승자 채널에만 붙는다
// (비승자 채널은 per-channel reason이 저장돼 있지 않음).
func edgeScenario(e HopEdge) HopScenario {
	src := nameOr(e.SourceName, e.SourceUID)
	dst := nameOr(e.TargetName, e.TargetUID)
	hs := HopScenario{
		SourceUID: e.SourceUID, SourceName: e.SourceName,
		TargetUID: e.TargetUID, TargetName: e.TargetName,
	}
	add := func(ch string, p float64) {
		if p <= 0 {
			return
		}
		c := HopChannel{Channel: ch, Prob: p}
		switch ch {
		case "network":
			c.Tactic = TacticLateral
			c.Scenario = fmt.Sprintf("%s에서 %s로 네트워크를 통해 직접 도달할 수 있습니다(측면 이동).", src, dst)
		case "rbac":
			c.Tactic = TacticExecution
			c.Scenario = fmt.Sprintf("%s의 SA 권한으로 %s 컨테이너에 들어가 명령을 실행할 수 있습니다(코드 실행).", src, dst)
		case "host":
			c.Tactic = TacticLateral
			c.Scenario = fmt.Sprintf("%s이 같은 노드(호스트)를 장악해 %s까지 손을 뻗칠 수 있습니다(측면 이동).", src, dst)
		}
		if e.WinChannel == ch {
			c.Reason = e.Reason
		}
		hs.Channels = append(hs.Channels, c)
	}
	// 표시 순서: network → rbac → host
	add("network", e.PNet)
	add("rbac", e.PRBAC)
	add("host", e.PHost)
	return hs
}

func nameOr(name, uid string) string {
	if name != "" {
		return name
	}
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}
