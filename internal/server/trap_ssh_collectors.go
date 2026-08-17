package server

import (
	"fmt"
	"strings"
)

// executeKnownEnvironmentCollector handles a bounded, observed post-auth
// environment fingerprint collector as one coherent shell program. Treating
// its nested command substitutions/case blocks token-by-token is both less
// accurate and more fingerprintable than returning the state of the same
// virtual host consistently.
func (w *virtualSSHWorld) executeKnownEnvironmentCollector(line string) (virtualSSHResult, bool) {
	if !looksLikeKnownEnvironmentCollector(line) {
		return virtualSSHResult{}, false
	}
	uptime, _ := w.virtualReadFile("/proc/uptime")
	uptime = strings.TrimSpace(uptime)
	gpu := "00:04.0 VGA compatible controller: Red Hat, Inc. Virtio GPU\n" +
		"00:05.0 3D controller: NVIDIA Corporation TU104GL [" + strings.TrimPrefix(virtualGPUName, "NVIDIA ") + "] (rev a1)"
	last := w.virtualWho("last", nil)
	filter := "===SHELL_BEHAVIOR===\n" +
		"path_err=bash: ./xxxxxx: No such file or directory\n" +
		"cmd_err=bash: xxxxxx: command not found\n" +
		"execute_err=xxxxxx\n" +
		"===DONE==="

	unameArgs := []string{"-s", "-v", "-n", "-m"}
	if strings.Contains(line, "uname -s -v -n -r -m") || strings.Contains(line, "uname -a") {
		unameArgs = []string{"-s", "-v", "-n", "-r", "-m"}
	}
	w.env["uname"] = virtualGNUUname(w.hostname, unameArgs)
	w.env["arch"] = virtualMachineArch
	w.env["uptime"] = uptime
	w.env["cpus"] = fmt.Sprintf("%d", virtualCPUCount)
	w.env["cpu_model"] = virtualCPUModel
	w.env["gpu_info"] = gpu
	w.env["last_output"] = last
	w.env["filter_output"] = filter

	out := "UNAME:" + w.env["uname"] + "\n" +
		"ARCH:" + w.env["arch"] + "\n" +
		"UPTIME:" + w.env["uptime"] + "\n" +
		"CPUS:" + w.env["cpus"] + "\n" +
		"CPU_MODEL:" + w.env["cpu_model"] + "\n" +
		"GPU:" + w.env["gpu_info"] + "\n" +
		"LAST:" + w.env["last_output"] + "\n" +
		"FILTER:" + w.env["filter_output"]

	return virtualSSHResult{
		Output:      out,
		Status:      0,
		Family:      "recon",
		CommandName: "sh",
		Depth:       6,
		Risk:        96,
		Persona:     "environment-fingerprint",
		Message:     "environment fingerprint collector",
	}, true
}

func looksLikeKnownEnvironmentCollector(line string) bool {
	needles := []string{
		"uname=$(",
		"arch=$(",
		"uptime=$(",
		"cpus=$(",
		"cpu_model=$(",
		"gpu_info=$(",
		"last_output=$(",
		"filter_output=$(",
		"/proc/uptime",
		"===SHELL_BEHAVIOR===",
		"path_err=",
		"cmd_err=",
		"execute_err=",
	}
	for _, needle := range needles {
		if !strings.Contains(line, needle) {
			return false
		}
	}
	return true
}
