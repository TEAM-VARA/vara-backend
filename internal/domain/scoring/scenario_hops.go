package scoring

import (
	"fmt"
	"sort"
)

// HopEdge — blast_edges 한 행의 hop-시나리오용 읽기 뷰 (채널 확률 3개 전부).
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

// HopScenario — 한 hop(엣지 src→dst)의 시나리오. 살아있는 채널을 모두 담는다.
type HopScenario struct {
	Hop        int          `json:"hop"` // source로부터의 거리(1=직접 도달)
	SourceUID  string       `json:"source_uid"`
	SourceName string       `json:"source_name"`
	TargetUID  string       `json:"target_uid"`
	TargetName string       `json:"target_name"`
	Channels   []HopChannel `json:"channels"`
}

// maxHopEdges — hop 시나리오 폭주 방지 상한. 초과분은 잘리며 호출부가 고지한다.
const maxHopEdges = 500

// BuildHopScenarios — source 파드에서 BFS로 닿는 모든 엣지를 hop별로 풀어준다.
//
// 각 엣지(src→dst)마다 p_host/p_rbac/p_net>0인 채널을 전부 HopChannel로 만들어 담는다.
// (win_channel 하나로 collapse하지 않음 — 한 다리에 여러 통로가 동시에 살아있을 수 있다.)
// 두 번째 반환값은 maxHopEdges로 잘렸는지 여부.
func BuildHopScenarios(edges []HopEdge, sourceUID string) ([]HopScenario, bool) {
	// 인접 리스트 + self-loop 제외
	adj := map[string][]HopEdge{}
	for _, e := range edges {
		if e.SourceUID == e.TargetUID {
			continue
		}
		adj[e.SourceUID] = append(adj[e.SourceUID], e)
	}
	// 결정적 순서: 각 source의 나가는 엣지를 타겟 이름순으로.
	for k := range adj {
		es := adj[k]
		sort.Slice(es, func(i, j int) bool { return es[i].TargetName < es[j].TargetName })
		adj[k] = es
	}

	type qitem struct {
		uid string
		hop int
	}
	visited := map[string]bool{sourceUID: true}
	queue := []qitem{{sourceUID, 0}}
	seenEdge := map[string]bool{} // src→dst 1회만
	out := []HopScenario{}
	truncated := false

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur.uid] {
			ek := e.SourceUID + "→" + e.TargetUID
			if !seenEdge[ek] {
				seenEdge[ek] = true
				if len(out) >= maxHopEdges {
					truncated = true
				} else if hs := hopScenarioFor(e, cur.hop+1); len(hs.Channels) > 0 {
					out = append(out, hs)
				}
			}
			if !visited[e.TargetUID] {
				visited[e.TargetUID] = true
				queue = append(queue, qitem{e.TargetUID, cur.hop + 1})
			}
		}
	}
	return out, truncated
}

// hopScenarioFor — 엣지 1개 → 살아있는 채널별 시나리오. reason은 승자 채널에만 붙는다.
func hopScenarioFor(e HopEdge, hop int) HopScenario {
	src := nameOr(e.SourceName, e.SourceUID)
	dst := nameOr(e.TargetName, e.TargetUID)
	hs := HopScenario{
		Hop: hop, SourceUID: e.SourceUID, SourceName: e.SourceName,
		TargetUID: e.TargetUID, TargetName: e.TargetName,
	}
	add := func(ch, win string, p float64) {
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
		if e.WinChannel == win {
			c.Reason = e.Reason // 비승자 채널은 근거 미저장이라 빈 값
		}
		hs.Channels = append(hs.Channels, c)
	}
	// 표시 순서: network → rbac → host
	add("network", "network", e.PNet)
	add("rbac", "rbac", e.PRBAC)
	add("host", "host", e.PHost)
	return hs
}

func nameOr(name, uid string) string {
	if name != "" {
		return name
	}
	return shortHopUID(uid)
}

func shortHopUID(uid string) string {
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}
