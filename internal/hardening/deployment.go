package hardening

import (
	"fmt"
	"sort"
	"strings"
)

func Deployment(c Config) (map[string]any, map[string]any) {
	image := "breachbench/" + c.Name + ":hardened"
	env := map[string]string{"HOME": "/tmp", "TMPDIR": "/tmp"}
	if c.Runtime != "php" {
		env["PORT"] = fmt.Sprint(c.Port)
	}
	if c.Runtime == "node" || c.Runtime == "next" {
		env["NODE_ENV"] = "production"
		env["HOSTNAME"] = "0.0.0.0"
	}
	var tmpfs []string
	for _, p := range c.Writable {
		tmpfs = append(tmpfs, fmt.Sprintf("%s:rw,noexec,nosuid,nodev,size=%dm,uid=65532,gid=65532,mode=0700", p, c.TempMiB))
	}
	composeEnv := map[string]string{}
	var kubeEnv []any
	for k, v := range c.Env {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := env[k]; ok {
			composeEnv[k] = strings.ReplaceAll(v, "$", "$$")
			kubeEnv = append(kubeEnv, map[string]any{"name": k, "value": v})
		}
	}
	for _, s := range c.Secrets {
		composeEnv[s.Env] = "${" + s.Env + ":?provide a least-privilege credential}"
		kubeEnv = append(kubeEnv, map[string]any{"name": s.Env, "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": s.Name, "key": s.Key}}})
	}
	service := map[string]any{"image": image, "build": map[string]any{"context": ".", "dockerfile": "Dockerfile"}, "platform": c.Platform, "user": "65532:65532", "read_only": true, "cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true", "seccomp=./seccomp.json"}, "network_mode": "none", "tmpfs": tmpfs, "pids_limit": c.PIDs, "mem_limit": fmt.Sprintf("%dm", c.MemoryMiB), "cpus": float64(c.CPUMillis) / 1000, "environment": composeEnv, "restart": "no"}
	compose := map[string]any{"services": map[string]any{c.Name: service}}
	labels := map[string]string{"app.kubernetes.io/name": c.Name, "app.kubernetes.io/managed-by": "breachbench"}
	metadata := func(name string) map[string]any { return map[string]any{"name": name, "labels": labels} }
	var volumes, mounts []any
	for i, p := range c.Writable {
		name := fmt.Sprintf("tmp-%d", i)
		volumes = append(volumes, map[string]any{"name": name, "emptyDir": map[string]string{"medium": "Memory", "sizeLimit": fmt.Sprintf("%dMi", c.TempMiB)}})
		mounts = append(mounts, map[string]any{"name": name, "mountPath": p})
	}
	security := map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "readOnlyRootFilesystem": true, "allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []string{"ALL"}}, "seccompProfile": map[string]string{"type": "Localhost", "localhostProfile": "breachbench/" + c.Name + ".json"}}
	probe := map[string]any{"tcpSocket": map[string]any{"port": c.Port}, "periodSeconds": 10}
	if c.HealthPath != "" {
		probe = map[string]any{"httpGet": map[string]any{"path": c.HealthPath, "port": c.Port}, "periodSeconds": 10}
	}
	container := map[string]any{"name": c.Name, "image": image, "ports": []any{map[string]any{"containerPort": c.Port}}, "securityContext": security, "env": kubeEnv, "volumeMounts": mounts, "readinessProbe": probe, "resources": map[string]any{"requests": map[string]string{"cpu": "100m", "memory": fmt.Sprintf("%dMi", c.MemoryMiB/2)}, "limits": map[string]string{"cpu": fmt.Sprintf("%dm", c.CPUMillis), "memory": fmt.Sprintf("%dMi", c.MemoryMiB), "ephemeral-storage": "128Mi"}}}
	pod := map[string]any{"serviceAccountName": c.Name, "automountServiceAccountToken": false, "enableServiceLinks": false, "securityContext": map[string]any{"fsGroup": 65532, "fsGroupChangePolicy": "OnRootMismatch"}, "containers": []any{container}, "volumes": volumes, "nodeSelector": map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": c.Platform[len("linux/"):]}}
	deployment := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata(c.Name), "spec": map[string]any{"replicas": 1, "selector": map[string]any{"matchLabels": labels}, "template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": pod}}}
	var egress = []any{}
	for _, e := range c.Egress {
		egress = append(egress, map[string]any{"to": []any{map[string]any{"ipBlock": map[string]string{"cidr": e.CIDR}}}, "ports": []any{map[string]any{"protocol": e.Protocol, "port": e.Port}}})
	}
	policy := map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": metadata(c.Name), "spec": map[string]any{"podSelector": map[string]any{"matchLabels": labels}, "policyTypes": []string{"Ingress", "Egress"}, "ingress": []any{map[string]any{"from": []any{map[string]any{"podSelector": map[string]any{}}}, "ports": []any{map[string]any{"protocol": "TCP", "port": c.Port}}}}, "egress": egress}}
	kubeService := map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": metadata(c.Name), "spec": map[string]any{"type": "ClusterIP", "selector": labels, "ports": []any{map[string]any{"port": c.Port, "targetPort": c.Port}}}}
	sa := map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata(c.Name), "automountServiceAccountToken": false}
	return compose, map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{sa, policy, deployment, kubeService}}
}
