package service

import (
	"testing"

	"github.com/vara/backend/internal/domain/scoring"
)

// rbacScoreWithout: 보완이 회수하는 RBAC 신호를 뺀 남은 최고 level (MAX 의미 검증).
func TestRbacScoreWithout(t *testing.T) {
	secretsExec := &scoring.AttackPathResult{
		RBACScore:   30, // secrets(30) > exec(25)
		RBACDetails: scoring.RBACDetails{HasSecretsAccess: true, HasPodExec: true},
	}
	if got := rbacScoreWithout(secretsExec, "MS-TA9025"); got != 25 {
		t.Errorf("secrets 제거: got %d, want 25 (exec 잔존)", got)
	}
	if got := rbacScoreWithout(secretsExec, "MS-TA9006"); got != 30 {
		t.Errorf("exec 제거(top 아님): got %d, want 30 (불변)", got)
	}
	if got := rbacScoreWithout(secretsExec, "MS-TA9015"); got != 30 {
		t.Errorf("비-level 보완(webhook): got %d, want 30 (불변→delta 0)", got)
	}

	adminSecrets := &scoring.AttackPathResult{
		RBACScore:   40,
		RBACDetails: scoring.RBACDetails{IsClusterAdmin: true, HasSecretsAccess: true},
	}
	if got := rbacScoreWithout(adminSecrets, "MS-TA9019"); got != 30 {
		t.Errorf("cluster-admin 제거: got %d, want 30 (secrets 잔존)", got)
	}

	secretsOnly := &scoring.AttackPathResult{
		RBACScore:   30,
		RBACDetails: scoring.RBACDetails{HasSecretsAccess: true},
	}
	if got := rbacScoreWithout(secretsOnly, "MS-TA9025"); got != 0 {
		t.Errorf("secrets 단독 제거: got %d, want 0", got)
	}
}

// mountScoreWithout: 같은 tier(30)를 만드는 다른 신호가 남으면 점수가 안 떨어진다.
func TestMountScoreWithout(t *testing.T) {
	both := scoring.MountDetails{HasPrivileged: true, HasHostPath: true}
	if got := mountScoreWithout(both, "MS-TA9018"); got != 30 {
		t.Errorf("priv 제거(hostPath 잔존): got %d, want 30", got)
	}
	if got := mountScoreWithout(both, "MS-TA9013"); got != 30 {
		t.Errorf("hostPath 제거(priv 잔존): got %d, want 30", got)
	}

	privOnly := scoring.MountDetails{HasPrivileged: true}
	if got := mountScoreWithout(privOnly, "MS-TA9018"); got != 0 {
		t.Errorf("priv 단독 제거: got %d, want 0", got)
	}
	hostPathOnly := scoring.MountDetails{HasHostPath: true}
	if got := mountScoreWithout(hostPathOnly, "MS-TA9013"); got != 0 {
		t.Errorf("hostPath 단독 제거: got %d, want 0", got)
	}

	privSecrets := scoring.MountDetails{HasPrivileged: true, SecretMounts: 2}
	if got := mountScoreWithout(privSecrets, "MS-TA9018"); got != 20 {
		t.Errorf("priv 제거(secret 2개 잔존): got %d, want 20", got)
	}
}
