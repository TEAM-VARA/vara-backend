package main

// VARA seed 도구.
// 1) ISMS-P 통제항목 JSON을 읽어 /api/v1/isms-p/controls 로 일괄 등록한다.
// 2) 등록된 control_id 각각에 대해 /api/v1/isms-p/mappings/run 을 호출해 매핑을 실행한다.
// K8s Job으로 한 번 실행되도록 설계되어 있다 (재실행 안전 — 컨트롤은 ON CONFLICT UPDATE).

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type ISMSControl struct {
	ControlID         string   `json:"control_id"`
	Domain            string   `json:"domain"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	Keywords          []string `json:"keywords"`
	GenerateEmbedding bool     `json:"generate_embedding"`
}

type MappingRunRequest struct {
	ControlID     string   `json:"control_id"`
	TopK          int      `json:"top_k"`
	MinSimilarity float64  `json:"min_similarity"`
	UseRAG        bool     `json:"use_rag"`
	UseRuleEngine bool     `json:"use_rule_engine"`
	SourceTypes   []string `json:"source_types"`
}

type MappingResult struct {
	MappingID int     `json:"mapping_id"`
	Status    string  `json:"status"`
	RiskLevel string  `json:"risk_level"`
	RiskScore float64 `json:"risk_score"`
	Summary   string  `json:"summary"`
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   struct {
		Message string `json:"message"`
	} `json:"error"`
}

func main() {
	apiBase := flag.String("api", envOr("VARA_API_BASE", "http://vara-api:8080"), "VARA API base URL")
	jsonPath := flag.String("file", envOr("ISMS_CONTROLS_FILE", "isms_p_controls.json"), "ISMS-P controls JSON file")
	runMapping := flag.Bool("run-mapping", envBool("RUN_MAPPING", true), "run /isms-p/mappings/run after seeding")
	topK := flag.Int("top-k", 10, "vector search Top-K")
	minSim := flag.Float64("min-sim", 0.5, "minimum cosine similarity")
	flag.Parse()

	controls, err := loadControls(*jsonPath)
	if err != nil {
		log.Fatalf("load controls: %v", err)
	}
	log.Printf("loaded %d ISMS-P controls from %s", len(controls), *jsonPath)

	client := &http.Client{Timeout: 120 * time.Second}

	if err := waitForAPI(client, *apiBase, 90*time.Second); err != nil {
		log.Fatalf("api not reachable: %v", err)
	}

	registered := 0
	for _, ctl := range controls {
		if err := postControl(client, *apiBase, ctl); err != nil {
			log.Printf("[FAIL] register %s: %v", ctl.ControlID, err)
			continue
		}
		log.Printf("[OK]   register %s — %s", ctl.ControlID, ctl.Title)
		registered++
	}
	log.Printf("registered %d / %d controls", registered, len(controls))

	if !*runMapping {
		return
	}

	for _, ctl := range controls {
		result, err := postMapping(client, *apiBase, MappingRunRequest{
			ControlID:     ctl.ControlID,
			TopK:          *topK,
			MinSimilarity: *minSim,
			UseRAG:        true,
			UseRuleEngine: true,
		})
		if err != nil {
			log.Printf("[FAIL] mapping %s: %v", ctl.ControlID, err)
			continue
		}
		log.Printf("[MAP]  %s → status=%s risk=%s score=%.2f mapping_id=%d",
			ctl.ControlID, result.Status, result.RiskLevel, result.RiskScore, result.MappingID)
	}
}

func loadControls(path string) ([]ISMSControl, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []ISMSControl
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func waitForAPI(client *http.Client, base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/api/v1/assets")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for %s", base)
}

func postJSON(client *http.Client, url string, payload any) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(raw))
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w (body=%s)", err, string(raw))
	}
	if !env.Success {
		return nil, fmt.Errorf("api error: %s", env.Error.Message)
	}
	return env.Data, nil
}

func postControl(client *http.Client, base string, ctl ISMSControl) error {
	_, err := postJSON(client, base+"/api/v1/isms-p/controls", ctl)
	return err
}

func postMapping(client *http.Client, base string, req MappingRunRequest) (*MappingResult, error) {
	data, err := postJSON(client, base+"/api/v1/isms-p/mappings/run", req)
	if err != nil {
		return nil, err
	}
	var result MappingResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode mapping result: %w", err)
	}
	return &result, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	switch os.Getenv(key) {
	case "1", "true", "TRUE", "yes":
		return true
	case "0", "false", "FALSE", "no":
		return false
	}
	return def
}
