package grc

import "testing"

// CanonicalID는 스코프별 안정적인 dedup 키를 만든다. 같은 결함이 N개 pod에 투영돼도
// 동일 id를 공유해 점수 합산 시 1회만 distinct로 계상되어야 한다.
func TestCanonicalID(t *testing.T) {
	tests := []struct {
		name        string
		scope       string
		clusterName string
		accountID   string
		assetKind   string
		assetUID    string
		ruleID      string
		want        string
	}{
		{"pod", ScopePod, "prod", "", "", "pod-uid-1", "R-2.6.1-01", "pod:pod-uid-1:R-2.6.1-01"},
		{"pod_chain", ScopePodChain, "prod", "", "sa", "sa-uid-9", "R-2.5.5-01", "sa:sa-uid-9:R-2.5.5-01"},
		{"cluster", ScopeCluster, "prod", "", "", "", "R-2.6.1-03", "cluster:prod:R-2.6.1-03"},
		{"account_no_asset", ScopeAccount, "prod", "1234567890", "", "", "R-2.9.4-01", "account:1234567890:R-2.9.4-01"},
		{"account_sg_resource", ScopeAccount, "prod", "1234567890", "sg", "sg-0abc", "R-2.6.6-01", "sg:sg-0abc:R-2.6.6-01"},
		{"unknown_falls_back_to_pod", "weird", "prod", "", "", "pod-uid-2", "R-X", "pod:pod-uid-2:R-X"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalID(tt.scope, tt.clusterName, tt.accountID, tt.assetKind, tt.assetUID, tt.ruleID)
			if got != tt.want {
				t.Fatalf("CanonicalID(%s) = %q, want %q", tt.scope, got, tt.want)
			}
		})
	}
}

// 클러스터 결함이 200개 pod에 투영돼도 canonical_id 1개로 묶여야 점수 폭발(N배)을 막는다.
func TestCanonicalID_StableAcrossFanout(t *testing.T) {
	id1 := CanonicalID(ScopeCluster, "prod", "", "", "pod-a", "R-2.6.1-03")
	id2 := CanonicalID(ScopeCluster, "prod", "", "", "pod-b", "R-2.6.1-03")
	if id1 != id2 {
		t.Fatalf("cluster canonical_id must ignore per-pod asset: %q vs %q", id1, id2)
	}
}

func TestIsInheritedScope(t *testing.T) {
	for scope, want := range map[string]bool{
		ScopeCluster:  true,
		ScopeAccount:  true,
		ScopePod:      false,
		ScopePodChain: false,
		"":            false,
	} {
		if got := IsInheritedScope(scope); got != want {
			t.Errorf("IsInheritedScope(%q) = %v, want %v", scope, got, want)
		}
	}
}

func TestOwnerHintForScope(t *testing.T) {
	for scope, want := range map[string]string{
		ScopeCluster:  OwnerClusterAdmin,
		ScopeAccount:  OwnerAccountAdmin,
		ScopePod:      OwnerWorkload,
		ScopePodChain: OwnerWorkload,
		"":            OwnerWorkload,
	} {
		if got := OwnerHintForScope(scope); got != want {
			t.Errorf("OwnerHintForScope(%q) = %q, want %q", scope, got, want)
		}
	}
}
