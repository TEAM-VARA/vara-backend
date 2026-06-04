package service

import (
	"strings"
	"testing"
)

// ── ExtractCloudEnvText ──

func TestExtractCloudEnvText_PodWithMetadata(t *testing.T) {
	rawData := map[string]any{
		"metadata": map[string]any{
			"name":      "web-abc",
			"namespace": "production",
			"labels": map[string]any{
				"app":     "web",
				"version": "v2",
			},
		},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":  "app",
					"image": "web:v2",
				},
			},
		},
	}

	text := ExtractCloudEnvText("pod", rawData)
	if text == "" {
		t.Fatal("expected non-empty text")
	}

	checks := []string{
		"resource_type: pod",
		"name: web-abc",
		"namespace: production",
		"label: app=web",
	}
	for _, c := range checks {
		if !strings.Contains(text, c) {
			t.Errorf("missing %q in:\n%s", c, text)
		}
	}
}

func TestExtractCloudEnvText_ServiceMinimal(t *testing.T) {
	rawData := map[string]any{
		"metadata": map[string]any{
			"name": "api-svc",
		},
	}

	text := ExtractCloudEnvText("service", rawData)
	if !strings.Contains(text, "resource_type: service") {
		t.Errorf("missing resource_type: %s", text)
	}
	if !strings.Contains(text, "name: api-svc") {
		t.Errorf("missing name: %s", text)
	}
}

func TestExtractCloudEnvText_NoMetadata(t *testing.T) {
	rawData := map[string]any{
		"kind":       "ConfigMap",
		"apiVersion": "v1",
	}

	text := ExtractCloudEnvText("configmap", rawData)
	if !strings.Contains(text, "resource_type: configmap") {
		t.Errorf("missing resource_type: %s", text)
	}
	// Should still have the JSON dump
	if !strings.Contains(text, "apiVersion") {
		t.Errorf("missing JSON content: %s", text)
	}
}

func TestExtractCloudEnvText_EmptyRawData(t *testing.T) {
	text := ExtractCloudEnvText("pod", map[string]any{})
	if !strings.Contains(text, "resource_type: pod") {
		t.Errorf("missing resource_type: %s", text)
	}
}

func TestExtractCloudEnvText_LargeJSON_Truncation(t *testing.T) {
	// Create a large raw_data that exceeds 4000 chars
	largeValue := strings.Repeat("x", 5000)
	rawData := map[string]any{
		"big_field": largeValue,
	}

	text := ExtractCloudEnvText("deployment", rawData)
	// The text should be truncated but still start correctly
	if !strings.Contains(text, "resource_type: deployment") {
		t.Errorf("missing resource_type header")
	}
	// The total length should be reasonable (resource_type line + truncated JSON)
	if len(text) > 5000 {
		t.Errorf("text too long (%d chars), expected truncation", len(text))
	}
}

func TestExtractCloudEnvText_RBACResource(t *testing.T) {
	rawData := map[string]any{
		"metadata": map[string]any{
			"name": "admin-role",
			"labels": map[string]any{
				"rbac.authorization.k8s.io/managed": "true",
			},
		},
		"rules": []any{
			map[string]any{
				"apiGroups": []any{""},
				"resources": []any{"pods", "services"},
				"verbs":     []any{"get", "list", "watch"},
			},
		},
	}

	text := ExtractCloudEnvText("rbac", rawData)
	if !strings.Contains(text, "resource_type: rbac") {
		t.Error("missing resource_type")
	}
	if !strings.Contains(text, "name: admin-role") {
		t.Error("missing name")
	}
}

func TestExtractCloudEnvText_NetworkPolicy(t *testing.T) {
	rawData := map[string]any{
		"metadata": map[string]any{
			"name":      "deny-all",
			"namespace": "secure-ns",
		},
		"spec": map[string]any{
			"podSelector": map[string]any{},
			"policyTypes": []any{"Ingress", "Egress"},
		},
	}

	text := ExtractCloudEnvText("networkpolicy", rawData)
	if !strings.Contains(text, "namespace: secure-ns") {
		t.Errorf("missing namespace: %s", text)
	}
	if !strings.Contains(text, "Ingress") {
		t.Errorf("missing policy type: %s", text)
	}
}
