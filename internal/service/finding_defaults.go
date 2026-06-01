package service

// Verdict type constants for compliance finding evaluation.
// Only 3 verdict types are valid as of migration 023.
const (
	VerdictCompliantIndicator = "compliant_indicator"
	VerdictPotentialFinding   = "potential_finding"
	VerdictNeedsReview        = "needs_review"
)
