package agent

// IsSATokenMounted reports whether a Pod's ServiceAccount token is actually
// mounted, given the Pod-level and SA-level automountServiceAccountToken values.
//
// 판정식(룰·침투그래프 공통):
//   - nil(미설정) = true. K8s 기본은 토큰 마운트다. false로 취급 금지.
//   - Pod가 SA를 override하므로 Pod∧SA 둘 다 마운트(true 또는 미설정)여야 실제 마운트.
//   - 하나라도 명시적 false면 토큰은 마운트되지 않는다.
func IsSATokenMounted(podAM *bool, saAM *bool) bool {
	podMounted := podAM == nil || *podAM
	saMounted := saAM == nil || *saAM
	return podMounted && saMounted
}
