package service

import "testing"

func TestParseFixtureRuleID(t *testing.T) {
	item, rid, err := ParseFixtureRuleID("R-2.2.1-07")
	if err != nil {
		t.Fatal(err)
	}
	if item != "2.2.1" || rid != "R-2.2.1-07" {
		t.Fatalf("got item=%q rid=%q", item, rid)
	}
}

func TestResolveItemAndRuleID_native(t *testing.T) {
	item, rid, err := ResolveItemAndRuleID("2.2.1-R007")
	if err != nil {
		t.Fatal(err)
	}
	if item != "2.2.1" || rid != "R-2.2.1-07" {
		t.Fatalf("got item=%q rid=%q", item, rid)
	}
}
