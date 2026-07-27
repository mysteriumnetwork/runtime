//go:build linux

/*
 * Copyright (C) 2026 The "MysteriumNetwork/node" Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package capabilities

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func detectDetailed() DetailedCapabilities {
	var detailed DetailedCapabilities

	detailed.UserNamespaces = probeNamespace("user", "max_user_namespaces")
	detailed.UserNSMappings = probeUserNSMappings(detailed.UserNamespaces)
	detailed.MountNamespaces = probeNamespace("mnt", "max_mnt_namespaces")
	detailed.PIDNamespaces = probeNamespace("pid", "max_pid_namespaces")
	detailed.NetworkNamespaces = probeNamespace("net", "max_net_namespaces")
	detailed.IPCNamespaces = probeNamespace("ipc", "max_ipc_namespaces")

	detailed.CgroupV2, detailed.WritableCgroupTree = probeCgroups()
	detailed.Seccomp = probeSeccomp()
	detailed.NoNewPrivileges = probeNoNewPrivileges()
	detailed.ReadOnlyRootFS = probeReadOnlyRootFS(detailed.MountNamespaces)

	return detailed
}

func probeNamespace(nsName, sysctlMaxName string) CapabilityStatus {
	nsPath := filepath.Join("/proc/self/ns", nsName)
	if _, err := os.Stat(nsPath); err != nil {
		if os.IsNotExist(err) {
			return StatusUnsupported
		}
		if os.IsPermission(err) {
			return StatusNoPerms
		}
		return StatusUnsupported
	}

	if sysctlMaxName != "" {
		sysctlPath := filepath.Join("/proc/sys/user", sysctlMaxName)
		if data, err := os.ReadFile(sysctlPath); err == nil {
			val := strings.TrimSpace(string(data))
			if num, err := strconv.Atoi(val); err == nil && num <= 0 {
				return StatusNoPerms
			}
		}
	}

	if nsName == "user" {
		if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
			val := strings.TrimSpace(string(data))
			if val == "0" && os.Geteuid() != 0 {
				return StatusNoPerms
			}
		}
	} else {
		// Non-user namespaces require root or an unprivileged user namespace clone capability.
		if os.Geteuid() != 0 {
			userNsStatus := probeNamespace("user", "max_user_namespaces")
			if userNsStatus != StatusSupported {
				return StatusNoPerms
			}
		}
	}

	return StatusSupported
}

func probeUserNSMappings(userNamespaceStatus CapabilityStatus) CapabilityStatus {
	if userNamespaceStatus != StatusSupported {
		return userNamespaceStatus
	}

	uidOwner := strconv.Itoa(os.Geteuid())
	gidOwner := strconv.Itoa(os.Getegid())
	if currentUser, err := user.Current(); err == nil && currentUser != nil && currentUser.Username != "" {
		uidOwner = currentUser.Username
		gidOwner = currentUser.Username
	}

	uidStatus := probeSubIDRange("/etc/subuid", uidOwner, strconv.Itoa(os.Geteuid()))
	gidStatus := probeSubIDRange("/etc/subgid", gidOwner, strconv.Itoa(os.Getegid()))

	if uidStatus == StatusNoPerms || gidStatus == StatusNoPerms {
		return StatusNoPerms
	}
	if uidStatus == StatusSupported && gidStatus == StatusSupported {
		return StatusSupported
	}

	return StatusUnsupported
}

func probeSubIDRange(filePath, owner, numericOwner string) CapabilityStatus {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsPermission(err) {
			return StatusNoPerms
		}
		return StatusUnsupported
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		entryOwner := strings.TrimSpace(parts[0])
		if entryOwner != owner && entryOwner != numericOwner {
			continue
		}

		count, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil {
			continue
		}
		if count > 0 {
			return StatusSupported
		}
	}

	return StatusUnsupported
}

func probeCgroups() (CapabilityStatus, CapabilityStatus) {
	mountPoint := "/sys/fs/cgroup"
	ctrlPath := filepath.Join(mountPoint, "cgroup.controllers")
	if _, err := os.Stat(ctrlPath); err != nil {
		if os.IsNotExist(err) {
			return StatusUnsupported, StatusUnsupported
		}
		if os.IsPermission(err) {
			return StatusNoPerms, StatusNoPerms
		}
		return StatusUnsupported, StatusUnsupported
	}

	cgroupV2Status := StatusSupported

	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		if os.IsPermission(err) {
			return cgroupV2Status, StatusNoPerms
		}
		return cgroupV2Status, StatusUnsupported
	}
	currentPath, ok := parseUnifiedCgroupPath(string(data))
	if !ok {
		return cgroupV2Status, StatusUnsupported
	}

	// A cgroup namespace normally presents its delegated root as "/". Enabling
	// domain controllers there would force the node into a child cgroup and
	// prevent Docker/containerd from attaching future exec processes to the
	// container root. Treat it as non-delegated.
	if !isDelegatedUnifiedCgroupPath(currentPath) {
		return cgroupV2Status, StatusNoPerms
	}

	probeDir := filepath.Join(mountPoint, strings.TrimPrefix(currentPath, "/"))
	if _, err := os.Stat(probeDir); err != nil {
		if os.IsPermission(err) {
			return cgroupV2Status, StatusNoPerms
		}
		return cgroupV2Status, StatusUnsupported
	}

	// Try to create a temporary child cgroup directory to test if cgroup tree is writable
	tempName := fmt.Sprintf("probe_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	testPath := filepath.Join(probeDir, tempName)

	err = os.Mkdir(testPath, 0o755)
	if err != nil {
		if os.IsPermission(err) || err == unix.EPERM || err == unix.EACCES || err == unix.EROFS {
			return cgroupV2Status, StatusNoPerms
		}
		return cgroupV2Status, StatusUnsupported
	}
	defer os.Remove(testPath)

	// Verify that cgroup.procs was automatically created by the kernel
	procsPath := filepath.Join(testPath, "cgroup.procs")
	if _, err := os.Stat(procsPath); err != nil {
		if os.IsPermission(err) {
			return cgroupV2Status, StatusNoPerms
		}
		return cgroupV2Status, StatusUnsupported
	}

	return cgroupV2Status, StatusSupported
}

func parseUnifiedCgroupPath(data string) (string, bool) {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		if path == "" {
			return "/", true
		}
		return filepath.Clean(path), true
	}
	return "", false
}

func isDelegatedUnifiedCgroupPath(path string) bool {
	return path != "" && filepath.Clean(path) != "/"
}

func probeSeccomp() CapabilityStatus {
	// Probe via prctl syscall
	_, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0, 0, 0, 0)
	if errno == unix.EINVAL {
		// Prctl PR_GET_SECCOMP invalid -> not supported
		return StatusUnsupported
	}
	if errno == unix.EPERM || errno == unix.EACCES {
		return StatusNoPerms
	}

	// Check /proc/self/status or /sys/kernel/security/seccomp as fallback validation
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
				if val == "0" || val == "1" || val == "2" {
					return StatusSupported
				}
			}
		}
	}

	if errno == 0 {
		return StatusSupported
	}
	return StatusSupported
}

func probeNoNewPrivileges() CapabilityStatus {
	res, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno == unix.EINVAL {
		return StatusUnsupported
	}
	if errno != 0 {
		return StatusNoPerms
	}
	if res == 0 || res == 1 {
		return StatusSupported
	}
	return StatusUnsupported
}

func probeReadOnlyRootFS(mountNsStatus CapabilityStatus) CapabilityStatus {
	if mountNsStatus == StatusSupported {
		return StatusSupported
	}
	if os.Geteuid() == 0 {
		return StatusSupported
	}
	return StatusNoPerms
}
