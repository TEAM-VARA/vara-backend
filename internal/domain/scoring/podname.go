package scoring

import "regexp"

// Deployment pod: name-{replicaset-hash}-{pod-hash}
// e.g. ts-gateway-service-566bb4f4ff-xk2kt → ts-gateway-service
var reDeploymentHash = regexp.MustCompile(`-[a-f0-9]{7,10}-[a-z0-9]{4,5}$`)

// DaemonSet pod: name-{pod-hash}
// e.g. vara-ebpf-agent-7wz5m → vara-ebpf-agent
var reDaemonSetHash = regexp.MustCompile(`-[a-z0-9]{5}$`)

// StatefulSet pod: name-{ordinal} — keep as-is
var reStatefulSetOrdinal = regexp.MustCompile(`-\d+$`)

// NormalizePodName strips Deployment/DaemonSet hash suffixes from pod names.
// StatefulSet ordinals (e.g. nacos-0) are preserved.
func NormalizePodName(name string) string {
	if reDeploymentHash.MatchString(name) {
		return reDeploymentHash.ReplaceAllString(name, "")
	}
	if reStatefulSetOrdinal.MatchString(name) {
		return name
	}
	if reDaemonSetHash.MatchString(name) {
		return reDaemonSetHash.ReplaceAllString(name, "")
	}
	return name
}
