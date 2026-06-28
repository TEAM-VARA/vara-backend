package service

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// fixtureRuleIDPattern matches rule IDs like R-2.2.1-07, R-2.5.4-05. Ruleset JSON files
// use this same R-{item}-{seq} shape, so it doubles as the native ruleset id.
var fixtureRuleIDPattern = regexp.MustCompile(`(?i)^R-([\d.]+)-(\d+)$`)

// legacyNativeRuleIDPattern matches the deprecated {item}-R### shape (e.g. 2.2.1-R007).
var legacyNativeRuleIDPattern = regexp.MustCompile(`(?i)^([\d.]+)-R0*(\d+)$`)

// ParseFixtureRuleID maps a rule_id (R-2.2.1-07) to its ISMS-P item id (2.2.1) and the
// ruleset JSON rule_id. Ruleset files use the same R-{item}-{seq} shape, so the rule id is
// returned with its sequence normalized to two digits (R-2.2.1-07).
func ParseFixtureRuleID(fixtureRuleID string) (itemID string, rulesetRuleID string, err error) {
	fixtureRuleID = strings.TrimSpace(fixtureRuleID)
	m := fixtureRuleIDPattern.FindStringSubmatch(fixtureRuleID)
	if m == nil {
		return "", "", fmt.Errorf("invalid fixture rule_id %q (expected R-{item}-{seq}, e.g. R-2.2.1-07)", fixtureRuleID)
	}
	itemID = m[1]
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", "", fmt.Errorf("invalid rule sequence in %q: %w", fixtureRuleID, err)
	}
	rulesetRuleID = fmt.Sprintf("R-%s-%02d", itemID, n)
	return itemID, rulesetRuleID, nil
}

// ResolveItemAndRuleID accepts a ruleset/fixture id (R-2.2.1-07) or the deprecated native
// id (2.2.1-R007) and returns the item id plus the canonical ruleset rule_id (R-2.2.1-07).
func ResolveItemAndRuleID(ruleRef string) (itemID string, rulesetRuleID string, err error) {
	ruleRef = strings.TrimSpace(ruleRef)
	if ruleRef == "" {
		return "", "", fmt.Errorf("empty rule reference")
	}
	// Deprecated native shape: "{item}-R###" (e.g. 2.2.1-R007) → R-{item}-{seq}.
	if m := legacyNativeRuleIDPattern.FindStringSubmatch(ruleRef); m != nil {
		n, convErr := strconv.Atoi(m[2])
		if convErr != nil {
			return "", "", fmt.Errorf("invalid rule sequence in %q: %w", ruleRef, convErr)
		}
		return m[1], fmt.Sprintf("R-%s-%02d", m[1], n), nil
	}
	return ParseFixtureRuleID(ruleRef)
}

func findRuleInRuleset(rs *Ruleset, rulesetRuleID string) (*Rule, error) {
	for i := range rs.Rules {
		if rs.Rules[i].RuleID == rulesetRuleID {
			return &rs.Rules[i], nil
		}
	}
	return nil, fmt.Errorf("rule %q not found in item %s ruleset", rulesetRuleID, rs.Item.ID)
}
