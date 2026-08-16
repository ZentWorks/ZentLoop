package server

import (
	"sort"
	"strings"

	"zentloop/internal/lures"
)

func (w *virtualSSHWorld) adaptToBehavior(family, command string) {
	key := strings.TrimSpace(strings.ToLower(family))
	if key == "" {
		key = "other"
	}
	w.interests[key]++
	low := strings.ToLower(command)
	if strings.Contains(low, "kube") || strings.Contains(low, "docker") || strings.Contains(low, "container") {
		w.interests["containers"]++
	}
	if strings.Contains(low, "password") || strings.Contains(low, "token") || strings.Contains(low, ".env") || strings.Contains(low, "credential") {
		w.interests["credentials"]++
	}
	if strings.Contains(low, "ssh ") || strings.Contains(low, "ping ") || strings.Contains(low, "nmap") || strings.Contains(low, "netstat") || strings.Contains(low, "ss ") {
		w.interests["network"]++
	}

	if w.interests["credentials"] >= 2 {
		w.seedCredentialLures()
	}
	if w.interests["containers"] >= 2 {
		w.seedContainerLures()
	}
	if w.interests["network"] >= 2 || w.interests["lateral"] >= 1 {
		w.seedNetworkLures()
	}
	if w.interests["persistence"] >= 1 || strings.Contains(low, "crontab") || strings.Contains(low, "systemctl") {
		w.seedPersistenceLures()
	}
	if w.interests["execution"] >= 2 || strings.Contains(low, "| bash") || strings.Contains(low, "| sh") {
		w.seedExecutionLures()
	}
	if looksLikeMinerCleanupSequence(low) {
		w.seedMinerCleanupLures()
		w.interests["execution"] += 2
		w.interests["persistence"] += 2
	}
}

func (w *virtualSSHWorld) seedCredentialLures() {
	_ = w.setVirtualDir("/etc/backup-agent")
	_ = w.setVirtualFile("/etc/backup-agent/credentials", "user=svc-backup\ntoken="+w.canaries["backup"]+"\nendpoint=ssh://backup-01\n")
	_ = w.setVirtualDir("/home/admin/.aws")
	_ = w.setVirtualFile("/home/admin/.aws/credentials", "[production]\naws_access_key_id=AKIA7Q2J5M4N8P3R9T1X\naws_secret_access_key="+w.canaries["internal-api"]+"\nregion=eu-central-1\n")
	_ = w.setVirtualFile("/opt/app/current/.npmrc", "@platform:registry=https://registry.internal/\n//registry.internal/:_authToken="+w.canaries["registry"]+"\n")
}

func (w *virtualSSHWorld) seedContainerLures() {
	_ = w.setVirtualDir("/home/admin/.kube")
	_ = w.setVirtualFile("/home/admin/.kube/config", "apiVersion: v1\nclusters:\n- cluster:\n    server: https://ops-gw-01:6443\n  name: prod\ncontexts:\n- context:\n    cluster: prod\n    namespace: platform\n    user: deployer\n  name: prod\ncurrent-context: prod\nusers:\n- name: deployer\n  user:\n    token: "+w.canaries["internal-api"]+"\n")
	_ = w.setVirtualDir("/opt/app/current/k8s")
	_ = w.setVirtualFile("/opt/app/current/k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: platform-web\nspec:\n  template:\n    spec:\n      imagePullSecrets:\n      - name: registry-prod\n      containers:\n      - name: web\n        image: registry.internal/platform/web:2026.08\n")
}

func (w *virtualSSHWorld) seedNetworkLures() {
	_ = w.setVirtualDir("/etc/ansible")
	_ = w.setVirtualFile("/etc/ansible/hosts", lures.Inventory())
	_ = w.setVirtualFile("/opt/app/current/network-notes.txt", "prod VLAN: 10.10.30.0/24\nbackup jump: svc-backup@backup-01\noperations gateway: ops-gw-01\nregistry: registry.internal\ngit: git.prod.internal\n")
}

func (w *virtualSSHWorld) seedPersistenceLures() {
	_ = w.setVirtualDir("/var/spool")
	_ = w.setVirtualDir("/var/spool/cron")
	_ = w.setVirtualDir("/var/spool/cron/crontabs")
	_ = w.setVirtualFile("/var/spool/cron/crontabs/root", "17 * * * * /usr/local/bin/health-sync --quiet\n0 2 * * * /usr/local/bin/backupctl sync --profile legacy\n")
	_ = w.setVirtualFile("/etc/systemd/system/platform-maintenance.service", "[Unit]\nDescription=Platform Maintenance Worker\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=root\nEnvironmentFile=/opt/app/.env\nExecStart=/usr/local/bin/platform-maintenance --registry registry.internal\nRestart=on-failure\n")
}

func (w *virtualSSHWorld) seedExecutionLures() {
	_ = w.setVirtualDir("/opt/app/current/scripts")
	_ = w.setVirtualFile("/opt/app/current/scripts/deploy-worker.sh", "#!/bin/sh\nset -e\nREGISTRY=${REGISTRY_HOST:-registry.internal}\necho logging into $REGISTRY\necho \"$REGISTRY_TOKEN\" | docker login $REGISTRY --username deploy --password-stdin\ndocker pull $REGISTRY/platform/worker:2026.08\n")
}

func (w *virtualSSHWorld) CanaryTouches(command string) []string {
	var hits []string
	for label, token := range w.canaries {
		if token != "" && strings.Contains(command, token) {
			hits = append(hits, label)
		}
	}
	sort.Strings(hits)
	return hits
}

func (w *virtualSSHWorld) currentHost() lures.Host {
	if h, ok := lures.Resolve(w.hostname); ok {
		return h
	}
	if h, ok := lures.Resolve("prod-app-02"); ok {
		return h
	}
	return lures.Host{Name: w.hostname, IP: "10.10.30.21", Role: "application"}
}

func looksLikeMinerCleanupSequence(low string) bool {
	markers := 0
	for _, needle := range []string{"pkill xmrig", "killall xmrig", "pkill cnrig", "history -c", "chattr -iae", "/dev/shm/", "/var/tmp/", "crontab -r"} {
		if strings.Contains(low, needle) {
			markers++
		}
	}
	return markers >= 3
}
