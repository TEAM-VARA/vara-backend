package service

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// fixtureRuleIDPattern matches test fixture IDs like R-2.2.1-07, R-1.1.4-11.
var fixtureRuleIDPattern = regexp.MustCompile(`(?i)^R-([\d.]+)-(\d+)$`)

// ParseFixtureRuleID maps fixture rule_id (R-2.2.1-07) to ISMS-P item id (2.2.1) and
// ruleset JSON rule_id (2.2.1-R007). Ruleset files use isms_p_{item}_ruleset.json.
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
	rulesetRuleID = fmt.Sprintf("%s-R%03d", itemID, n)
	return itemID, rulesetRuleID, nil
}

// ResolveItemAndRuleID accepts either a fixture id (R-2.2.1-07) or a native ruleset id (2.2.1-R007).
func ResolveItemAndRuleID(ruleRef string) (itemID string, rulesetRuleID string, err error) {
	ruleRef = strings.TrimSpace(ruleRef)
	if ruleRef == "" {
		return "", "", fmt.Errorf("empty rule reference")
	}
	// Native ruleset shape: "{item}-R###" with item containing dots (1.2.1, 2.2.1, …).
	if strings.Contains(ruleRef, "-R") && !strings.HasPrefix(strings.ToUpper(ruleRef), "R-") {
		idx := strings.LastIndex(ruleRef, "-R")
		if idx <= 0 {
			return "", "", fmt.Errorf("invalid ruleset rule_id %q", ruleRef)
		}
		itemID = ruleRef[:idx]
		return itemID, ruleRef, nil
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
