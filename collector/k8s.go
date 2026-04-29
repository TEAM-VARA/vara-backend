package main

// Kubernetes 자산/노출도 수집기.
// - Pod → asset (asset_type=pod)
// - LoadBalancer Service / NodePort Service / Ingress → 백엔드 Pod에 exposure 등록
// - In-cluster ServiceAccount 토큰을 사용하며, 로컬 개발 시에는 KUBECONFIG fallback이 적용된다.

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type K8sCollector struct {
	cs        kubernetes.Interface
	cluster   string
	cloud     string
	namespace string
}

func NewK8sCollector(cluster, cloud, namespace, kubeconfigPath string) (*K8sCollector, error) {
	cfg, err := loadK8sConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &K8sCollector{cs: cs, cluster: cluster, cloud: cloud, namespace: namespace}, nil
}

func loadK8sConfig(kubeconfigPath string) (*rest.Config, error) {
	// In-cluster (Pod 안에서 실행될 때 ServiceAccount 토큰을 자동 사용).
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	// 로컬 개발 fallback.
	if kubeconfigPath == "" {
		return nil, fmt.Errorf("no in-cluster config and KUBECONFIG not provided")
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
}

// CollectAssets는 대상 namespace의 Pod 목록을 자산으로 변환한다.
// container[0].image를 자산의 image로 사용하며, 멀티 컨테이너 Pod는 첫 컨테이너 기준으로 단순화한다.
func (k *K8sCollector) CollectAssets(ctx context.Context) ([]Asset, error) {
	pods, err := k.cs.CoreV1().Pods(k.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		image := ""
		if len(p.Spec.Containers) > 0 {
			image = p.Spec.Containers[0].Image
		}
		out = append(out, Asset{
			AssetID:        podAssetID(k.cluster, p.Namespace, p.Name),
			AssetType:      "pod",
			Name:           p.Name,
			Namespace:      p.Namespace,
			Cluster:        k.cluster,
			CloudProvider:  k.cloud,
			Image:          image,
			ServiceAccount: p.Spec.ServiceAccountName,
			Metadata: map[string]any{
				"node_name":   p.Spec.NodeName,
				"phase":       string(p.Status.Phase),
				"labels":      p.Labels,
				"host_network": p.Spec.HostNetwork,
				"privileged":   anyPrivileged(p),
			},
		})
	}
	return out, nil
}

// CollectExposures는 LoadBalancer/NodePort Service와 Ingress를 검사해 백엔드 Pod에 외부 노출 정보를 부여한다.
// - LoadBalancer with external hostname/IP → E4
// - NodePort → E3
// - Ingress with hostname → E4 (auth annotation 있으면 E3 + auth_required=true)
// 동일한 Pod에 여러 노출이 존재할 수 있다(예: LoadBalancer + Ingress).
func (k *K8sCollector) CollectExposures(ctx context.Context) ([]Exposure, error) {
	svcs, err := k.cs.CoreV1().Services(k.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	ingresses, err := k.cs.NetworkingV1().Ingresses(k.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	out := []Exposure{}

	// 1) LoadBalancer / NodePort Service → backend pods.
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		level, entrypoint := classifyService(svc)
		if level == "" {
			continue
		}
		pods, err := k.podsMatchingSelector(ctx, svc.Namespace, svc.Spec.Selector)
		if err != nil {
			return nil, err
		}
		for _, p := range pods {
			for _, port := range svc.Spec.Ports {
				out = append(out, Exposure{
					AssetID:       podAssetID(k.cluster, p.Namespace, p.Name),
					ExposureLevel: level,
					ExposureType:  "k8s_service_" + strings.ToLower(string(svc.Spec.Type)),
					Entrypoint:    entrypoint,
					Protocol:      strings.ToLower(string(port.Protocol)),
					Port:          int(port.Port),
					AuthRequired:  false,
					Description: fmt.Sprintf(
						"Service %s/%s (type=%s) 가 Pod %s/%s를 외부에 노출한다.",
						svc.Namespace, svc.Name, svc.Spec.Type, p.Namespace, p.Name,
					),
					Metadata: map[string]any{
						"service":      svc.Name,
						"service_type": string(svc.Spec.Type),
					},
				})
			}
		}
	}

	// 2) Ingress → service → backend pods.
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		entrypoint := ingressEntrypoint(ing)
		if entrypoint == "" {
			continue
		}
		auth := hasAuthAnnotation(ing.Annotations)
		level := "E4"
		if auth {
			level = "E3"
		}
		// Ingress가 가리키는 모든 Service backend 수집.
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				if p.Backend.Service == nil {
					continue
				}
				svc, err := k.cs.CoreV1().Services(ing.Namespace).Get(ctx, p.Backend.Service.Name, metav1.GetOptions{})
				if err != nil {
					continue
				}
				pods, err := k.podsMatchingSelector(ctx, svc.Namespace, svc.Spec.Selector)
				if err != nil {
					continue
				}
				port := int(p.Backend.Service.Port.Number)
				for _, pod := range pods {
					out = append(out, Exposure{
						AssetID:       podAssetID(k.cluster, pod.Namespace, pod.Name),
						ExposureLevel: level,
						ExposureType:  "k8s_ingress",
						Entrypoint:    entrypoint + p.Path,
						Protocol:      "http",
						Port:          port,
						AuthRequired:  auth,
						Description: fmt.Sprintf(
							"Ingress %s/%s 가 host=%s path=%s 로 Pod %s/%s를 인터넷에 노출한다.",
							ing.Namespace, ing.Name, rule.Host, p.Path, pod.Namespace, pod.Name,
						),
						Metadata: map[string]any{
							"ingress": ing.Name,
							"host":    rule.Host,
						},
					})
				}
			}
		}
	}

	return out, nil
}

func (k *K8sCollector) podsMatchingSelector(ctx context.Context, ns string, sel map[string]string) ([]corev1.Pod, error) {
	if len(sel) == 0 {
		return nil, nil
	}
	pods, err := k.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(sel).String(),
	})
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

func classifyService(svc *corev1.Service) (level, entrypoint string) {
	switch svc.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ing.Hostname != "" {
				return "E4", ing.Hostname
			}
			if ing.IP != "" {
				return "E4", ing.IP
			}
		}
		// LoadBalancer 인데 아직 endpoint가 안 잡힌 경우.
		return "E3", svc.Name
	case corev1.ServiceTypeNodePort:
		return "E3", svc.Name
	}
	return "", ""
}

func ingressEntrypoint(ing *netv1.Ingress) string {
	for _, rule := range ing.Spec.Rules {
		if rule.Host != "" {
			scheme := "http"
			if len(ing.Spec.TLS) > 0 {
				scheme = "https"
			}
			return fmt.Sprintf("%s://%s", scheme, rule.Host)
		}
	}
	for _, lb := range ing.Status.LoadBalancer.Ingress {
		if lb.Hostname != "" {
			return "http://" + lb.Hostname
		}
		if lb.IP != "" {
			return "http://" + lb.IP
		}
	}
	return ""
}

func hasAuthAnnotation(ann map[string]string) bool {
	for k := range ann {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "auth-url") ||
			strings.Contains(lk, "auth-type") ||
			strings.Contains(lk, "auth-signin") ||
			strings.Contains(lk, "oauth2") {
			return true
		}
	}
	return false
}

func anyPrivileged(p *corev1.Pod) bool {
	for _, c := range p.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

func podAssetID(cluster, ns, name string) string {
	return fmt.Sprintf("pod://%s/%s/%s", cluster, ns, name)
}
