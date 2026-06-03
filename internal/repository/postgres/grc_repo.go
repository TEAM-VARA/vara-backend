package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/grc"
)

type GRCRepo struct {
	pg *pgxpool.Pool
}

func NewGRCRepo(pg *pgxpool.Pool) *GRCRepo {
	return &GRCRepo{pg: pg}
}

// ── Check lifecycle ──

// CreateCheck inserts a new compliance check.
func (r *GRCRepo) CreateCheck(ctx context.Context, chk *grc.Check) error {
	_, err := r.pg.Exec(ctx, `
		INSERT INTO grc_checks (check_id, company_id, isms_p_item_id, ruleset_version,
		                        status, progress_pct, auto_collect, submitted_at, check_source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, chk.CheckID, chk.CompanyID, chk.ISMSPItemID, chk.RulesetVersion,
		chk.Status, chk.ProgressPct, chk.AutoCollect, chk.SubmittedAt,
		nilStrPtr(chk.CheckSource))
	return err
}

// UpdateCheckStarted marks a check as running.
func (r *GRCRepo) UpdateCheckStarted(ctx context.Context, checkID string) error {
	now := time.Now().UTC()
	_, err := r.pg.Exec(ctx, `
		UPDATE grc_checks SET status = 'running', started_at = $2, updated_at = NOW()
		WHERE check_id = $1
	`, checkID, now)
	return err
}

// UpdateCheckProgress updates progress percentage.
func (r *GRCRepo) UpdateCheckProgress(ctx context.Context, checkID string, pct int) error {
	_, err := r.pg.Exec(ctx, `
		UPDATE grc_checks SET progress_pct = $2, updated_at = NOW()
		WHERE check_id = $1
	`, checkID, pct)
	return err
}

// UpdateCheckFailed marks a check as failed.
func (r *GRCRepo) UpdateCheckFailed(ctx context.Context, checkID string, errDetail *grc.ErrorDetail) error {
	errJSON, err := json.Marshal(errDetail)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = r.pg.Exec(ctx, `
		UPDATE grc_checks SET status = 'failed', completed_at = $2, error = $3, updated_at = NOW()
		WHERE check_id = $1
	`, checkID, now, errJSON)
	return err
}

// SaveCheckResult persists the completed check results in a single transaction.
// Updates grc_checks summary + inserts grc_rule_results, grc_violations, grc_recommendations.
func (r *GRCRepo) SaveCheckResult(ctx context.Context, result *grc.ComplianceCheckResult) error {
	tx, err := r.pg.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Update grc_checks with summary
	_, err = tx.Exec(ctx, `
		UPDATE grc_checks SET
			status = 'completed', progress_pct = 100,
			completed_at = $2, verdict = $3, severity = $4, summary_text = $5,
			total_rules = $6, passed_rules = $7, failed_rules = $8,
			skipped_rules = $9, evidence_count = $10, updated_at = NOW()
		WHERE check_id = $1
	`, result.CheckID, result.CompletedAt, result.Verdict, result.Severity,
		result.Summary.SummaryText,
		result.Summary.TotalRules, result.Summary.Passed,
		result.Summary.Failed, result.Summary.Skipped,
		result.Summary.EvidenceCollected)
	if err != nil {
		return fmt.Errorf("update check: %w", err)
	}

	// 2. Insert rule results + violations
	for _, rr := range result.RuleResults {
		srcJSON, mErr := json.Marshal(rr.EvidenceSources)
		if mErr != nil {
			return fmt.Errorf("marshal evidence_sources: %w", mErr)
		}
		evidenceJSON, mErr := json.Marshal(rr.Evidence)
		if mErr != nil {
			return fmt.Errorf("marshal evidence_json: %w", mErr)
		}
		if string(evidenceJSON) == "null" {
			evidenceJSON = []byte("{}")
		}
		affectedJSON, mErr := json.Marshal(rr.AffectedResources)
		if mErr != nil {
			return fmt.Errorf("marshal affected_resources: %w", mErr)
		}
		if string(affectedJSON) == "null" {
			affectedJSON = []byte("[]")
		}

		jMode := rr.JudgmentMode
		if jMode == "" {
			jMode = "auto"
		}
		var matchedVal *bool
		if jMode == "manual" {
			matchedVal = &rr.Matched
		}

		var rrID int64
		err = tx.QueryRow(ctx, `
			INSERT INTO grc_rule_results
				(check_id, rule_id, check_category, evidence_type, system,
				 verdict, evidence_files, evidence_sources, matched_indicators, skip_reason,
				 embedding_similarity,
				 judgment_mode, verdict_type, matched, observation, evidence_json,
				 affected_resources, manual_check_areas, additional_review_items,
				 automation_coverage, alternative_controls, compliance_mappings,
				 kisa_defect_case_refs, deferred, deferred_reason, isms_p_item_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,
			        $12,$13,$14,$15,$16::jsonb,
			        $17::jsonb,$18,$19,
			        $20,$21,$22,
			        $23,$24,$25,$26)
			RETURNING id
		`, result.CheckID, rr.RuleID, rr.CheckCategory, rr.EvidenceType, rr.System,
			rr.Verdict, rr.EvidenceFiles, srcJSON, rr.MatchedIndicators, rr.SkipReason,
			rr.EmbeddingSimilarity,
			jMode, nilStrPtr(rr.VerdictType), matchedVal, nilStrPtr(rr.Observation), evidenceJSON,
			affectedJSON, jsonOrNil(rr.ManualCheckAreas), jsonOrNil(rr.AdditionalReviewItems),
			jsonOrNil(rr.AutomationCoverage), jsonOrNil(rr.AlternativeControls), jsonOrNil(rr.ComplianceMappings),
			jsonOrNil(rr.KisaDefectCaseRefs), rr.Deferred, nilStrPtr(rr.DeferredReason), nilStrPtr(rr.ISMSPItemID),
		).Scan(&rrID)
		if err != nil {
			return fmt.Errorf("insert rule_result %s: %w", rr.RuleID, err)
		}

		for _, v := range rr.Violations {
			_, err = tx.Exec(ctx, `
				INSERT INTO grc_violations
					(rule_result_id, field, pattern, expected, actual, description, severity,
					 k8s_cluster, k8s_namespace, k8s_kind, k8s_name, k8s_container)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			`, rrID, v.Field, v.Pattern,
				fmt.Sprintf("%v", v.Expected), fmt.Sprintf("%v", v.Actual),
				v.Description, v.Severity,
				nilStrPtr(v.K8sSource.ClusterName), nilStrPtr(v.K8sSource.Namespace),
				nilStrPtr(v.K8sSource.ResourceKind), nilStrPtr(v.K8sSource.ResourceName),
				nilStrPtr(v.K8sSource.ContainerName))
			if err != nil {
				return fmt.Errorf("insert violation for %s: %w", rr.RuleID, err)
			}
		}
	}

	// 3. Insert recommendations
	for _, rec := range result.Recommendations {
		_, err = tx.Exec(ctx, `
			INSERT INTO grc_recommendations (check_id, rule_id, action, reference)
			VALUES ($1,$2,$3,$4)
		`, result.CheckID, rec.RuleID, rec.Action, rec.Reference)
		if err != nil {
			return fmt.Errorf("insert recommendation %s: %w", rec.RuleID, err)
		}
	}

	return tx.Commit(ctx)
}

// ── Check queries ──

// GetCheck retrieves a check by ID.
func (r *GRCRepo) GetCheck(ctx context.Context, checkID string) (*grc.Check, error) {
	var chk grc.Check
	var errJSON []byte
	var verdict, severity, summaryText *string
	var totalRules, passedRules, failedRules, skippedRules, evidenceCount *int

	err := r.pg.QueryRow(ctx, `
		SELECT check_id, company_id, isms_p_item_id, ruleset_version,
		       status, progress_pct, auto_collect,
		       submitted_at, started_at, completed_at,
		       verdict, severity, summary_text,
		       total_rules, passed_rules, failed_rules, skipped_rules, evidence_count,
		       error, created_at, updated_at
		FROM grc_checks WHERE check_id = $1
	`, checkID).Scan(
		&chk.CheckID, &chk.CompanyID, &chk.ISMSPItemID, &chk.RulesetVersion,
		&chk.Status, &chk.ProgressPct, &chk.AutoCollect,
		&chk.SubmittedAt, &chk.StartedAt, &chk.CompletedAt,
		&verdict, &severity, &summaryText,
		&totalRules, &passedRules, &failedRules, &skippedRules, &evidenceCount,
		&errJSON, &chk.CreatedAt, &chk.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if verdict != nil {
		chk.Verdict = *verdict
	}
	if severity != nil {
		chk.Severity = *severity
	}
	if summaryText != nil {
		chk.SummaryText = *summaryText
	}
	if totalRules != nil {
		chk.TotalRules = *totalRules
	}
	if passedRules != nil {
		chk.PassedRules = *passedRules
	}
	if failedRules != nil {
		chk.FailedRules = *failedRules
	}
	if skippedRules != nil {
		chk.SkippedRules = *skippedRules
	}
	if evidenceCount != nil {
		chk.EvidenceCount = *evidenceCount
	}
	if len(errJSON) > 0 {
		var ed grc.ErrorDetail
		if e := json.Unmarshal(errJSON, &ed); e == nil {
			chk.Error = &ed
		}
	}
	return &chk, nil
}

// GetCheckRuleResults retrieves all rule results (with violations) for a check.
func (r *GRCRepo) GetCheckRuleResults(ctx context.Context, checkID string) ([]grc.RuleResult, error) {
	rows, err := r.pg.Query(ctx, `
		SELECT id, rule_id, check_category, evidence_type, system,
		       verdict, evidence_files, evidence_sources, matched_indicators, skip_reason,
		       embedding_similarity,
		       judgment_mode, verdict_type, matched, observation, evidence_json,
		       affected_resources, manual_check_areas, additional_review_items,
		       automation_coverage, alternative_controls, compliance_mappings,
		       kisa_defect_case_refs, deferred, deferred_reason, isms_p_item_id
		FROM grc_rule_results WHERE check_id = $1
		ORDER BY rule_id
	`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []grc.RuleResult
	for rows.Next() {
		var rr grc.RuleResult
		var evidenceType, system, skipReason *string
		var embSim *float64
		var srcRaw []byte
		// manual-mode nullable fields
		var verdictType, observation, deferredReason, ismsPItemID *string
		var matchedVal *bool
		var evidenceRaw, affectedRaw []byte
		var manualCheckRaw, additionalReviewRaw json.RawMessage
		var automationRaw, alternativeRaw, complianceRaw, kisaRaw json.RawMessage

		if err := rows.Scan(
			&rr.ID, &rr.RuleID, &rr.CheckCategory, &evidenceType, &system,
			&rr.Verdict, &rr.EvidenceFiles, &srcRaw, &rr.MatchedIndicators, &skipReason,
			&embSim,
			&rr.JudgmentMode, &verdictType, &matchedVal, &observation, &evidenceRaw,
			&affectedRaw, &manualCheckRaw, &additionalReviewRaw,
			&automationRaw, &alternativeRaw, &complianceRaw,
			&kisaRaw, &rr.Deferred, &deferredReason, &ismsPItemID,
		); err != nil {
			return nil, err
		}
		if evidenceType != nil {
			rr.EvidenceType = *evidenceType
		}
		if system != nil {
			rr.System = *system
		}
		if skipReason != nil {
			rr.SkipReason = *skipReason
		}
		if embSim != nil {
			rr.EmbeddingSimilarity = embSim
		}
		if len(srcRaw) > 0 {
			_ = json.Unmarshal(srcRaw, &rr.EvidenceSources)
		}
		if verdictType != nil {
			rr.VerdictType = *verdictType
		}
		if matchedVal != nil {
			rr.Matched = *matchedVal
		}
		if observation != nil {
			rr.Observation = *observation
		}
		if deferredReason != nil {
			rr.DeferredReason = *deferredReason
		}
		if ismsPItemID != nil {
			rr.ISMSPItemID = *ismsPItemID
		}
		if len(evidenceRaw) > 0 && string(evidenceRaw) != "{}" {
			_ = json.Unmarshal(evidenceRaw, &rr.Evidence)
		}
		if len(affectedRaw) > 0 && string(affectedRaw) != "[]" {
			_ = json.Unmarshal(affectedRaw, &rr.AffectedResources)
		}
		rr.ManualCheckAreas = manualCheckRaw
		rr.AdditionalReviewItems = additionalReviewRaw
		rr.AutomationCoverage = automationRaw
		rr.AlternativeControls = alternativeRaw
		rr.ComplianceMappings = complianceRaw
		rr.KisaDefectCaseRefs = kisaRaw

		results = append(results, rr)
	}

	// Load violations for all rule results in one query
	if len(results) > 0 {
		rrIDs := make([]int64, len(results))
		rrIDMap := make(map[int64]int) // rrID → index in results
		for i, rr := range results {
			rrIDs[i] = rr.ID
			rrIDMap[rr.ID] = i
		}

		vRows, err := r.pg.Query(ctx, `
			SELECT rule_result_id, field, pattern, expected, actual, description, severity,
			       k8s_cluster, k8s_namespace, k8s_kind, k8s_name, k8s_container
			FROM grc_violations WHERE rule_result_id = ANY($1)
			ORDER BY id
		`, rrIDs)
		if err != nil {
			return nil, err
		}
		defer vRows.Close()

		for vRows.Next() {
			var v grc.Violation
			var rrID int64
			var field, pattern, expected, actual *string
			var k8sCluster, k8sNs, k8sKind, k8sName, k8sContainer *string
			if err := vRows.Scan(&rrID, &field, &pattern, &expected, &actual, &v.Description, &v.Severity,
				&k8sCluster, &k8sNs, &k8sKind, &k8sName, &k8sContainer); err != nil {
				return nil, err
			}
			if field != nil {
				v.Field = *field
			}
			if pattern != nil {
				v.Pattern = *pattern
			}
			if expected != nil {
				v.Expected = *expected
			}
			if actual != nil {
				v.Actual = *actual
			}
			if k8sCluster != nil {
				v.K8sSource.ClusterName = *k8sCluster
			}
			if k8sNs != nil {
				v.K8sSource.Namespace = *k8sNs
			}
			if k8sKind != nil {
				v.K8sSource.ResourceKind = *k8sKind
			}
			if k8sName != nil {
				v.K8sSource.ResourceName = *k8sName
			}
			if k8sContainer != nil {
				v.K8sSource.ContainerName = *k8sContainer
			}
			if idx, ok := rrIDMap[rrID]; ok {
				results[idx].Violations = append(results[idx].Violations, v)
			}
		}
	}

	return results, nil
}

// GetCheckRecommendations retrieves recommendations for a check.
func (r *GRCRepo) GetCheckRecommendations(ctx context.Context, checkID string) ([]grc.Recommendation, error) {
	rows, err := r.pg.Query(ctx, `
		SELECT rule_id, action, reference
		FROM grc_recommendations WHERE check_id = $1
		ORDER BY id
	`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recs []grc.Recommendation
	for rows.Next() {
		var rec grc.Recommendation
		if err := rows.Scan(&rec.RuleID, &rec.Action, &rec.Reference); err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// CheckFilters contains optional filters for listing checks.
type CheckFilters struct {
	CompanyID   string
	ISMSPItemID string
	Verdict     string
	Status      string
}

// ListChecks returns paginated compliance checks with optional filters.
func (r *GRCRepo) ListChecks(ctx context.Context, filters CheckFilters, page, pageSize int) ([]grc.CheckListItem, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Build WHERE clause
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if filters.CompanyID != "" {
		where += fmt.Sprintf(" AND company_id = $%d", argIdx)
		args = append(args, filters.CompanyID)
		argIdx++
	}
	if filters.ISMSPItemID != "" {
		where += fmt.Sprintf(" AND isms_p_item_id = $%d", argIdx)
		args = append(args, filters.ISMSPItemID)
		argIdx++
	}
	if filters.Verdict != "" {
		where += fmt.Sprintf(" AND verdict = $%d", argIdx)
		args = append(args, filters.Verdict)
		argIdx++
	}
	if filters.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filters.Status)
		argIdx++
	}

	// Count total
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM grc_checks " + where
	if err := r.pg.QueryRow(ctx, countQuery, args...).Scan(&totalCount); err != nil {
		return nil, 0, err
	}

	// Fetch page
	offset := (page - 1) * pageSize
	listQuery := fmt.Sprintf(`
		SELECT check_id, company_id, isms_p_item_id, status, verdict, severity,
		       total_rules, passed_rules, failed_rules, skipped_rules, evidence_count,
		       submitted_at, completed_at
		FROM grc_checks %s
		ORDER BY submitted_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := r.pg.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []grc.CheckListItem
	for rows.Next() {
		var item grc.CheckListItem
		var verdict, severity *string
		var totalRules, passedRules, failedRules, skippedRules, evidenceCount *int
		if err := rows.Scan(
			&item.CheckID, &item.CompanyID, &item.ISMSPItemID, &item.Status,
			&verdict, &severity,
			&totalRules, &passedRules, &failedRules, &skippedRules, &evidenceCount,
			&item.SubmittedAt, &item.CompletedAt,
		); err != nil {
			return nil, 0, err
		}
		if verdict != nil {
			item.Verdict = *verdict
		}
		if severity != nil {
			item.Severity = *severity
		}
		if totalRules != nil {
			item.TotalRules = *totalRules
		}
		if passedRules != nil {
			item.PassedRules = *passedRules
		}
		if failedRules != nil {
			item.FailedRules = *failedRules
		}
		if skippedRules != nil {
			item.SkippedRules = *skippedRules
		}
		if evidenceCount != nil {
			item.EvidenceCount = *evidenceCount
		}
		items = append(items, item)
	}

	return items, totalCount, nil
}

// ── Evidence ──

// InsertEvidenceFile records an uploaded evidence file (with optional content_hash).
func (r *GRCRepo) InsertEvidenceFile(ctx context.Context, ef *grc.EvidenceFile) error {
	var k8sArg any
	if ef.K8sSource.HasAny() {
		b, err := json.Marshal(ef.K8sSource)
		if err != nil {
			return fmt.Errorf("marshal k8s_source: %w", err)
		}
		k8sArg = b
	}
	_, err := r.pg.Exec(ctx, `
		INSERT INTO grc_evidence_files
			(check_id, filename, evidence_type, system, description,
			 storage_path, file_size_bytes, target_rule_ids, content_hash, k8s_source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, ef.CheckID, ef.Filename, ef.EvidenceType, ef.System, ef.Description,
		ef.StoragePath, ef.FileSizeBytes, ef.TargetRuleIDs, nilStrPtr(ef.ContentHash), k8sArg)
	return err
}

// FindExtractedTextByHash looks up a previously extracted text by file content hash.
// Returns the extracted text and true if found, or empty string and false if not cached.
func (r *GRCRepo) FindExtractedTextByHash(ctx context.Context, contentHash string) (string, bool, error) {
	var text *string
	err := r.pg.QueryRow(ctx, `
		SELECT extracted_text FROM grc_evidence_files
		WHERE content_hash = $1
		  AND extracted_text IS NOT NULL AND extracted_text != ''
		LIMIT 1
	`, contentHash).Scan(&text)
	if err != nil {
		return "", false, nil // not found or error → treat as cache miss
	}
	if text != nil && *text != "" {
		return *text, true, nil
	}
	return "", false, nil
}

func nilStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// jsonOrNil returns nil when r is empty (so nullable JSONB columns store NULL),
// otherwise returns the raw bytes for insertion.
func jsonOrNil(r json.RawMessage) interface{} {
	if len(r) == 0 {
		return nil
	}
	return []byte(r)
}

// UpdateEvidenceExtractedText saves the OCR/PDF extracted text for an evidence file.
func (r *GRCRepo) UpdateEvidenceExtractedText(ctx context.Context, checkID, filename, text string) error {
	_, err := r.pg.Exec(ctx, `
		UPDATE grc_evidence_files SET extracted_text = $3
		WHERE check_id = $1 AND filename = $2
	`, checkID, filename, text)
	return err
}

// ListEvidenceFiles returns all evidence files for a check.
func (r *GRCRepo) ListEvidenceFiles(ctx context.Context, checkID string) ([]grc.EvidenceFile, error) {
	rows, err := r.pg.Query(ctx, `
		SELECT id, check_id, filename, evidence_type, system, description,
		       storage_path, file_size_bytes, target_rule_ids, extracted_text, content_hash,
		       k8s_source, created_at
		FROM grc_evidence_files WHERE check_id = $1
		ORDER BY id
	`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []grc.EvidenceFile
	for rows.Next() {
		var f grc.EvidenceFile
		var system, description, extractedText, contentHash *string
		var k8sRaw []byte
		if err := rows.Scan(
			&f.ID, &f.CheckID, &f.Filename, &f.EvidenceType,
			&system, &description, &f.StoragePath, &f.FileSizeBytes,
			&f.TargetRuleIDs, &extractedText, &contentHash,
			&k8sRaw, &f.CreatedAt,
		); err != nil {
			return nil, err
		}
		if system != nil {
			f.System = *system
		}
		if description != nil {
			f.Description = *description
		}
		if extractedText != nil {
			f.ExtractedText = *extractedText
		}
		if contentHash != nil {
			f.ContentHash = *contentHash
		}
		if len(k8sRaw) > 0 {
			_ = json.Unmarshal(k8sRaw, &f.K8sSource)
		}
		files = append(files, f)
	}
	return files, nil
}

// ListEvidenceForAPI returns evidence list items (without extracted_text content).
func (r *GRCRepo) ListEvidenceForAPI(ctx context.Context, checkID string) ([]grc.EvidenceListItem, error) {
	rows, err := r.pg.Query(ctx, `
		SELECT id, filename, evidence_type, system, description,
		       file_size_bytes, target_rule_ids,
		       (extracted_text IS NOT NULL AND extracted_text != '') AS has_extracted_text,
		       k8s_source, created_at
		FROM grc_evidence_files WHERE check_id = $1
		ORDER BY id
	`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []grc.EvidenceListItem
	for rows.Next() {
		var item grc.EvidenceListItem
		var system, description *string
		var k8sRaw []byte
		if err := rows.Scan(
			&item.ID, &item.Filename, &item.EvidenceType,
			&system, &description, &item.FileSizeBytes,
			&item.TargetRuleIDs, &item.HasExtractedText,
			&k8sRaw, &item.CreatedAt,
		); err != nil {
			return nil, err
		}
		if system != nil {
			item.System = *system
		}
		if description != nil {
			item.Description = *description
		}
		if len(k8sRaw) > 0 {
			_ = json.Unmarshal(k8sRaw, &item.K8sSource)
		}
		items = append(items, item)
	}
	return items, nil
}

// ── Embedding ──

// UpdateEvidenceEmbeddings saves guideline text and embedding vectors for an evidence file.
func (r *GRCRepo) UpdateEvidenceEmbeddings(ctx context.Context, checkID, filename string, guidelineText string, evidenceEmb, guidelineEmb []float32) error {
	_, err := r.pg.Exec(ctx, `
		UPDATE grc_evidence_files
		SET guideline_text = $3,
		    evidence_embedding = $4::vector,
		    guideline_embedding = $5::vector
		WHERE check_id = $1 AND filename = $2
	`, checkID, filename, nilStrPtr(guidelineText), vectorToString(evidenceEmb), vectorToString(guidelineEmb))
	return err
}

// ListEvidenceEmbeddingsForCheck returns evidence_embedding vectors keyed by filename (pgvector → text → parse).
func (r *GRCRepo) ListEvidenceEmbeddingsForCheck(ctx context.Context, checkID string) (map[string][]float32, error) {
	rows, err := r.pg.Query(ctx, `
		SELECT filename, evidence_embedding::text
		FROM grc_evidence_files
		WHERE check_id = $1 AND evidence_embedding IS NOT NULL
	`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string][]float32)
	for rows.Next() {
		var fn string
		var embText *string
		if err := rows.Scan(&fn, &embText); err != nil {
			return nil, err
		}
		if embText == nil || *embText == "" {
			continue
		}
		vec, err := parseVectorText(*embText)
		if err != nil || len(vec) == 0 {
			continue
		}
		out[fn] = vec
	}
	return out, rows.Err()
}

func parseVectorText(s string) ([]float32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty vector text")
	}
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	parts := strings.Split(s, ",")
	out := make([]float32, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseFloat(p, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, float32(v))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no vector components")
	}
	return out, nil
}

// FindSimilarEvidence searches for evidence files with similar embeddings using cosine distance.
func (r *GRCRepo) FindSimilarEvidence(ctx context.Context, queryEmb []float32, limit int) ([]grc.EvidenceFile, error) {
	if len(queryEmb) == 0 || limit <= 0 {
		return nil, nil
	}

	rows, err := r.pg.Query(ctx, `
		SELECT id, check_id, filename, evidence_type, system, description,
		       storage_path, file_size_bytes, target_rule_ids, extracted_text, content_hash, created_at
		FROM grc_evidence_files
		WHERE evidence_embedding IS NOT NULL
		ORDER BY evidence_embedding <=> $1::vector
		LIMIT $2
	`, vectorToString(queryEmb), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []grc.EvidenceFile
	for rows.Next() {
		var f grc.EvidenceFile
		var system, description, extractedText, contentHash *string
		if err := rows.Scan(
			&f.ID, &f.CheckID, &f.Filename, &f.EvidenceType,
			&system, &description, &f.StoragePath, &f.FileSizeBytes,
			&f.TargetRuleIDs, &extractedText, &contentHash, &f.CreatedAt,
		); err != nil {
			return nil, err
		}
		if system != nil {
			f.System = *system
		}
		if description != nil {
			f.Description = *description
		}
		if extractedText != nil {
			f.ExtractedText = *extractedText
		}
		if contentHash != nil {
			f.ContentHash = *contentHash
		}
		files = append(files, f)
	}
	return files, nil
}

// ── Cloud Environments ──

// InsertCloudEnvironment inserts a new cloud environment resource.
func (r *GRCRepo) InsertCloudEnvironment(ctx context.Context, env *grc.CloudEnvironment) error {
	rawJSON, err := json.Marshal(env.RawData)
	if err != nil {
		return fmt.Errorf("marshal raw_data: %w", err)
	}

	err = r.pg.QueryRow(ctx, `
		INSERT INTO grc_cloud_environments
			(company_id, check_id, resource_type, resource_name,
			 namespace, cluster_name, raw_data, extracted_text, embedding)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::vector)
		RETURNING id, created_at
	`, env.CompanyID, nilStrPtr(env.CheckID), env.ResourceType, env.ResourceName,
		nilStrPtr(env.Namespace), nilStrPtr(env.ClusterName),
		rawJSON, nilStrPtr(env.ExtractedText), vectorToString(env.Embedding),
	).Scan(&env.ID, &env.CreatedAt)
	return err
}

// ListCloudEnvironments returns paginated cloud environment resources.
func (r *GRCRepo) ListCloudEnvironments(ctx context.Context, companyID, resourceType string, page, pageSize int) ([]grc.CloudEnvListItem, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	where := "WHERE company_id = $1"
	args := []any{companyID}
	argIdx := 2

	if resourceType != "" {
		where += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, resourceType)
		argIdx++
	}

	var totalCount int
	if err := r.pg.QueryRow(ctx,
		"SELECT COUNT(*) FROM grc_cloud_environments "+where, args...,
	).Scan(&totalCount); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	listQuery := fmt.Sprintf(`
		SELECT id, company_id, check_id, resource_type, resource_name,
		       namespace, cluster_name,
		       (embedding IS NOT NULL) AS has_embedding,
		       created_at
		FROM grc_cloud_environments %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := r.pg.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []grc.CloudEnvListItem
	for rows.Next() {
		var item grc.CloudEnvListItem
		var checkID, namespace, clusterName *string
		if err := rows.Scan(
			&item.ID, &item.CompanyID, &checkID, &item.ResourceType, &item.ResourceName,
			&namespace, &clusterName, &item.HasEmbedding, &item.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		if checkID != nil {
			item.CheckID = *checkID
		}
		if namespace != nil {
			item.Namespace = *namespace
		}
		if clusterName != nil {
			item.ClusterName = *clusterName
		}
		items = append(items, item)
	}
	return items, totalCount, nil
}

// ── Pod Graph Evaluations ──

// SavePodGraphEvaluation inserts a pod graph evaluation result.
func (r *GRCRepo) SavePodGraphEvaluation(ctx context.Context, companyID, clusterName, podName, namespace, verdict string, totalRules, passed, failed, skipped int, ruleResults any, summary any) (int64, error) {
	ruleResultsJSON, err := json.Marshal(ruleResults)
	if err != nil {
		return 0, fmt.Errorf("marshal rule_results: %w", err)
	}
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return 0, fmt.Errorf("marshal summary: %w", err)
	}

	var id int64
	err = r.pg.QueryRow(ctx, `
		INSERT INTO grc_pod_graph_evaluations
			(company_id, cluster_name, pod_name, namespace, overall_verdict,
			 total_rules, passed, failed, skipped, rule_results, summary)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, companyID, nilStrPtr(clusterName), podName, nilStrPtr(namespace),
		verdict, totalRules, passed, failed, skipped, ruleResultsJSON, summaryJSON).Scan(&id)
	return id, err
}

// ListPodGraphEvaluations returns paginated pod graph evaluation results.
func (r *GRCRepo) ListPodGraphEvaluations(ctx context.Context, companyID string, page, pageSize int) ([]grc.PodGraphEvalListItem, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if companyID != "" {
		where += fmt.Sprintf(" AND company_id = $%d", argIdx)
		args = append(args, companyID)
		argIdx++
	}

	var totalCount int
	if err := r.pg.QueryRow(ctx,
		"SELECT COUNT(*) FROM grc_pod_graph_evaluations "+where, args...,
	).Scan(&totalCount); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	listQuery := fmt.Sprintf(`
		SELECT id, company_id, cluster_name, pod_name, namespace,
		       overall_verdict, total_rules, passed, failed, skipped, created_at
		FROM grc_pod_graph_evaluations %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := r.pg.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []grc.PodGraphEvalListItem
	for rows.Next() {
		var item grc.PodGraphEvalListItem
		var clusterName, namespace *string
		if err := rows.Scan(
			&item.ID, &item.CompanyID, &clusterName, &item.PodName, &namespace,
			&item.OverallVerdict, &item.TotalRules, &item.Passed, &item.Failed,
			&item.Skipped, &item.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		if clusterName != nil {
			item.ClusterName = *clusterName
		}
		if namespace != nil {
			item.Namespace = *namespace
		}
		items = append(items, item)
	}

	return items, totalCount, nil
}

// GetPodGraphEvaluation returns a single pod graph evaluation with full rule_results.
func (r *GRCRepo) GetPodGraphEvaluation(ctx context.Context, id int64) (*grc.PodGraphEvalListItem, json.RawMessage, error) {
	var item grc.PodGraphEvalListItem
	var clusterName, namespace *string
	var ruleResultsRaw json.RawMessage

	err := r.pg.QueryRow(ctx, `
		SELECT id, company_id, cluster_name, pod_name, namespace,
		       overall_verdict, total_rules, passed, failed, skipped, rule_results, created_at
		FROM grc_pod_graph_evaluations WHERE id = $1
	`, id).Scan(
		&item.ID, &item.CompanyID, &clusterName, &item.PodName, &namespace,
		&item.OverallVerdict, &item.TotalRules, &item.Passed, &item.Failed,
		&item.Skipped, &ruleResultsRaw, &item.CreatedAt,
	)
	if err != nil {
		return nil, nil, err
	}
	if clusterName != nil {
		item.ClusterName = *clusterName
	}
	if namespace != nil {
		item.Namespace = *namespace
	}
	return &item, ruleResultsRaw, nil
}

// GetLatestPodGraphEvalByPod returns the most recent pod graph evaluation for a
// specific pod (identified by companyID + clusterName + namespace + podName).
func (r *GRCRepo) GetLatestPodGraphEvalByPod(ctx context.Context, companyID, clusterName, namespace, podName string) (*grc.PodGraphEvalListItem, error) {
	var item grc.PodGraphEvalListItem
	var clusterNamePtr, namespacePtr *string

	err := r.pg.QueryRow(ctx, `
		SELECT id, company_id, cluster_name, pod_name, namespace,
		       overall_verdict, total_rules, passed, failed, skipped, created_at
		FROM grc_pod_graph_evaluations
		WHERE company_id = $1
		  AND cluster_name = $2
		  AND namespace = $3
		  AND pod_name = $4
		ORDER BY created_at DESC
		LIMIT 1
	`, companyID, nilStrPtr(clusterName), nilStrPtr(namespace), podName).Scan(
		&item.ID, &item.CompanyID, &clusterNamePtr, &item.PodName, &namespacePtr,
		&item.OverallVerdict, &item.TotalRules, &item.Passed, &item.Failed,
		&item.Skipped, &item.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if clusterNamePtr != nil {
		item.ClusterName = *clusterNamePtr
	}
	if namespacePtr != nil {
		item.Namespace = *namespacePtr
	}
	return &item, nil
}

// ── Item Violations (ISMS-P 항목별 위반 자산 조회) ──

// ViolatedPodRow is a row returned by the ISMS-P item violation query.
type ViolatedPodRow struct {
	PodName       string
	Namespace     string
	ViolatedRules []string
	ISMSPItemName string
}

// GetViolatedAssetsByISMSPItem returns pods that violate rules under a specific ISMS-P item.
// Queries the latest evaluation per pod, filters rule_results JSONB by item_id and verdict.
func (r *GRCRepo) GetViolatedAssetsByISMSPItem(
	ctx context.Context,
	companyID, clusterName, ismspItemID string,
) ([]ViolatedPodRow, error) {
	rows, err := r.pg.Query(ctx, `
		WITH latest_evals AS (
			SELECT DISTINCT ON (company_id, cluster_name, namespace, pod_name)
			       pod_name, namespace, rule_results
			FROM grc_pod_graph_evaluations
			WHERE company_id = $1
			  AND cluster_name = $2
			ORDER BY company_id, cluster_name, namespace, pod_name, created_at DESC
		)
		SELECT le.pod_name,
		       le.namespace,
		       jsonb_agg(rr->>'rule_id') AS violated_rule_ids,
		       (array_agg(rr->>'isms_p_item_name'))[1] AS item_name
		FROM latest_evals le,
		     jsonb_array_elements(le.rule_results) AS rr
		WHERE rr->>'isms_p_item' = $3
		  AND rr->>'verdict' = '미준수'
		GROUP BY le.pod_name, le.namespace
	`, companyID, nilStrPtr(clusterName), ismspItemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ViolatedPodRow
	for rows.Next() {
		var row ViolatedPodRow
		var namespace *string
		var rulesJSON json.RawMessage
		if err := rows.Scan(&row.PodName, &namespace, &rulesJSON, &row.ISMSPItemName); err != nil {
			return nil, err
		}
		if namespace != nil {
			row.Namespace = *namespace
		}
		if err := json.Unmarshal(rulesJSON, &row.ViolatedRules); err != nil {
			return nil, fmt.Errorf("unmarshal violated_rule_ids: %w", err)
		}
		result = append(result, row)
	}
	return result, nil
}

// ── Cluster Compliance Results (통합 클러스터 컴플라이언스 저장) ──

// SaveClusterComplianceResult persists a cluster compliance evaluation result.
func (r *GRCRepo) SaveClusterComplianceResult(ctx context.Context, result *grc.ClusterComplianceResult) (int64, error) {
	itemsJSON, err := json.Marshal(result.Items)
	if err != nil {
		return 0, fmt.Errorf("marshal items: %w", err)
	}

	var id int64
	err = r.pg.QueryRow(ctx, `
		INSERT INTO grc_cluster_compliance_results
			(company_id, cluster_name, snapshot_at, evaluated_at,
			 total_items, compliant_items, non_compliant_items, needs_review_items,
			 total_rules, total_pods, items)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, result.CompanyID, result.ClusterName, result.SnapshotAt, result.EvaluatedAt,
		result.TotalItems, result.CompliantItems, result.NonCompliantItems, result.NeedsReviewItems,
		result.TotalRules, result.TotalPods, itemsJSON).Scan(&id)
	return id, err
}

// GetLatestClusterComplianceResult returns the most recent cluster compliance result.
func (r *GRCRepo) GetLatestClusterComplianceResult(ctx context.Context, companyID, clusterName string) (*grc.ClusterComplianceResult, error) {
	var result grc.ClusterComplianceResult
	var itemsRaw json.RawMessage

	err := r.pg.QueryRow(ctx, `
		SELECT company_id, cluster_name, snapshot_at, evaluated_at,
		       total_items, compliant_items, non_compliant_items, needs_review_items,
		       total_rules, total_pods, items
		FROM grc_cluster_compliance_results
		WHERE company_id = $1 AND cluster_name = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, companyID, clusterName).Scan(
		&result.CompanyID, &result.ClusterName, &result.SnapshotAt, &result.EvaluatedAt,
		&result.TotalItems, &result.CompliantItems, &result.NonCompliantItems, &result.NeedsReviewItems,
		&result.TotalRules, &result.TotalPods, &itemsRaw,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(itemsRaw, &result.Items); err != nil {
		return nil, fmt.Errorf("unmarshal items: %w", err)
	}
	return &result, nil
}

// ── Guidelines ──

// InsertGuideline inserts a new guideline record.
func (r *GRCRepo) InsertGuideline(ctx context.Context, g *grc.Guideline) error {
	return r.pg.QueryRow(ctx, `
		INSERT INTO grc_guidelines
			(company_id, isms_p_item_id, filename, storage_path,
			 file_size_bytes, content_hash, extracted_text, embedding)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::vector)
		RETURNING id, uploaded_at, updated_at
	`, g.CompanyID, g.ISMSPItemID, g.Filename, g.StoragePath,
		g.FileSizeBytes, nilStrPtr(g.ContentHash),
		nilStrPtr(g.ExtractedText), vectorToString(g.Embedding),
	).Scan(&g.ID, &g.UploadedAt, &g.UpdatedAt)
}

// UpdateGuidelineText updates the extracted text and embedding for a guideline.
func (r *GRCRepo) UpdateGuidelineText(ctx context.Context, id int64, text string, emb []float32) error {
	_, err := r.pg.Exec(ctx, `
		UPDATE grc_guidelines
		SET extracted_text = $2, embedding = $3::vector, updated_at = NOW()
		WHERE id = $1
	`, id, nilStrPtr(text), vectorToString(emb))
	return err
}

// ListGuidelines returns guideline list items for a company and optional item.
func (r *GRCRepo) ListGuidelines(ctx context.Context, companyID, ismspItemID string) ([]grc.GuidelineListItem, error) {
	where := "WHERE company_id = $1"
	args := []any{companyID}
	if ismspItemID != "" {
		where += " AND (isms_p_item_id = $2 OR isms_p_item_id IS NULL)"
		args = append(args, ismspItemID)
	}

	rows, err := r.pg.Query(ctx, fmt.Sprintf(`
		SELECT id, company_id, isms_p_item_id, filename, file_size_bytes,
		       (extracted_text IS NOT NULL AND extracted_text != '') AS has_extracted_text,
		       (embedding IS NOT NULL) AS has_embedding,
		       uploaded_at
		FROM grc_guidelines %s
		ORDER BY uploaded_at DESC
	`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []grc.GuidelineListItem
	for rows.Next() {
		var item grc.GuidelineListItem
		if err := rows.Scan(
			&item.ID, &item.CompanyID, &item.ISMSPItemID, &item.Filename,
			&item.FileSizeBytes, &item.HasExtractedText, &item.HasEmbedding,
			&item.UploadedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// GetGuidelinesForItem returns full guideline records (with embedding) for compliance evaluation.
func (r *GRCRepo) GetGuidelinesForItem(ctx context.Context, companyID, ismspItemID string) ([]grc.Guideline, error) {
	rows, err := r.pg.Query(ctx, `
		SELECT id, company_id, isms_p_item_id, filename, storage_path,
		       file_size_bytes, content_hash, extracted_text,
		       embedding::text, uploaded_at, updated_at
		FROM grc_guidelines
		WHERE company_id = $1 AND (isms_p_item_id = $2 OR isms_p_item_id IS NULL)
		ORDER BY isms_p_item_id NULLS LAST, uploaded_at DESC
	`, companyID, ismspItemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var guidelines []grc.Guideline
	for rows.Next() {
		var g grc.Guideline
		var contentHash, extractedText, embText *string
		if err := rows.Scan(
			&g.ID, &g.CompanyID, &g.ISMSPItemID, &g.Filename, &g.StoragePath,
			&g.FileSizeBytes, &contentHash, &extractedText,
			&embText, &g.UploadedAt, &g.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if contentHash != nil {
			g.ContentHash = *contentHash
		}
		if extractedText != nil {
			g.ExtractedText = *extractedText
		}
		if embText != nil && *embText != "" {
			vec, err := parseVectorText(*embText)
			if err == nil {
				g.Embedding = vec
			}
		}
		guidelines = append(guidelines, g)
	}
	return guidelines, nil
}

// DeleteGuideline deletes a guideline by ID.
func (r *GRCRepo) DeleteGuideline(ctx context.Context, id int64) error {
	tag, err := r.pg.Exec(ctx, `DELETE FROM grc_guidelines WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guideline not found: %d", id)
	}
	return nil
}

// GetGuideline returns a single guideline by ID.
func (r *GRCRepo) GetGuideline(ctx context.Context, id int64) (*grc.Guideline, error) {
	var g grc.Guideline
	var contentHash, extractedText *string
	err := r.pg.QueryRow(ctx, `
		SELECT id, company_id, isms_p_item_id, filename, storage_path,
		       file_size_bytes, content_hash, extracted_text,
		       uploaded_at, updated_at
		FROM grc_guidelines WHERE id = $1
	`, id).Scan(
		&g.ID, &g.CompanyID, &g.ISMSPItemID, &g.Filename, &g.StoragePath,
		&g.FileSizeBytes, &contentHash, &extractedText,
		&g.UploadedAt, &g.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if contentHash != nil {
		g.ContentHash = *contentHash
	}
	if extractedText != nil {
		g.ExtractedText = *extractedText
	}
	return &g, nil
}

// FindGuidelineTextByHash looks up previously extracted text by content hash.
func (r *GRCRepo) FindGuidelineTextByHash(ctx context.Context, hash string) (string, bool, error) {
	var text *string
	err := r.pg.QueryRow(ctx, `
		SELECT extracted_text FROM grc_guidelines
		WHERE content_hash = $1
		  AND extracted_text IS NOT NULL AND extracted_text != ''
		LIMIT 1
	`, hash).Scan(&text)
	if err != nil {
		return "", false, nil
	}
	if text != nil && *text != "" {
		return *text, true, nil
	}
	return "", false, nil
}

// FindGuidelineEmbeddingByHash looks up a previously generated embedding by content hash.
// Returns the embedding vector and true if found, or nil and false if not cached.
func (r *GRCRepo) FindGuidelineEmbeddingByHash(ctx context.Context, hash string) ([]float32, bool, error) {
	var vecText *string
	err := r.pg.QueryRow(ctx, `
		SELECT embedding::text FROM grc_guidelines
		WHERE content_hash = $1
		  AND embedding IS NOT NULL
		LIMIT 1
	`, hash).Scan(&vecText)
	if err != nil {
		return nil, false, nil // not found or error → treat as cache miss
	}
	if vecText == nil || *vecText == "" {
		return nil, false, nil
	}
	emb, err := parseVectorText(*vecText)
	if err != nil {
		return nil, false, nil
	}
	return emb, true, nil
}

// UpdateCheckGuidelineIDs saves the guideline IDs used in a check.
func (r *GRCRepo) UpdateCheckGuidelineIDs(ctx context.Context, checkID string, guidelineIDs []int64) error {
	_, err := r.pg.Exec(ctx, `
		UPDATE grc_checks SET guideline_ids = $2, updated_at = NOW()
		WHERE check_id = $1
	`, checkID, guidelineIDs)
	return err
}

// ── Helpers ──

// vectorToString converts a float32 slice to a pgvector-compatible string "[0.1,0.2,...]".
// Returns nil-safe: empty/nil slice → nil string pointer for SQL NULL.
func vectorToString(v []float32) *string {
	if len(v) == 0 {
		return nil
	}
	parts := make([]string, len(v))
	for i, f := range v {
		parts[i] = fmt.Sprintf("%g", f)
	}
	s := "[" + strings.Join(parts, ",") + "]"
	return &s
}

// TotalPages calculates total pages for pagination.
func TotalPages(totalCount, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	return int(math.Ceil(float64(totalCount) / float64(pageSize)))
}

// ── Compliance Findings (historical archive - read-only) ──

// ListFindingClusterSummaries returns paginated cluster finding summaries.
func (r *GRCRepo) ListFindingClusterSummaries(ctx context.Context, companyID string, page, pageSize int) ([]grc.FindingClusterResult, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	where := "WHERE company_id = $1"
	args := []any{companyID}

	var totalCount int
	if err := r.pg.QueryRow(ctx,
		"SELECT COUNT(*) FROM finding_cluster_summaries "+where, args...,
	).Scan(&totalCount); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	listQuery := fmt.Sprintf(`
		SELECT id, company_id, cluster_name, namespace, snapshot_at, evaluated_at,
		       total_findings, matched_count, unmatched_count, by_verdict, findings_detail
		FROM finding_cluster_summaries %s
		ORDER BY evaluated_at DESC
		LIMIT $2 OFFSET $3
	`, where)
	args = append(args, pageSize, offset)

	rows, err := r.pg.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []grc.FindingClusterResult
	for rows.Next() {
		var item grc.FindingClusterResult
		var namespace *string
		var snapshotAt, evaluatedAt time.Time
		var byVerdictRaw, findingsDetailRaw json.RawMessage

		if err := rows.Scan(
			&item.ID, &item.CompanyID, &item.ClusterName, &namespace,
			&snapshotAt, &evaluatedAt,
			&item.TotalFindings, &item.MatchedCount, &item.UnmatchedCount,
			&byVerdictRaw, &findingsDetailRaw,
		); err != nil {
			return nil, 0, err
		}
		if namespace != nil {
			item.Namespace = *namespace
		}
		item.SnapshotAt = snapshotAt.Format(time.RFC3339)
		item.EvaluatedAt = evaluatedAt.Format(time.RFC3339)

		_ = json.Unmarshal(byVerdictRaw, &item.ByVerdict)
		_ = json.Unmarshal(findingsDetailRaw, &item.Findings)

		items = append(items, item)
	}
	return items, totalCount, nil
}
