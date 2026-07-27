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
	"sort"
	"strings"
)

// CapabilityStatus represents the outcome of probing a specific runtime capability.
type CapabilityStatus string

const (
	// StatusSupported indicates that the capability is available and supported by the kernel and environment.
	StatusSupported CapabilityStatus = "supported"
	// StatusUnsupported indicates that the capability is not supported by the underlying OS or kernel.
	StatusUnsupported CapabilityStatus = "unsupported"
	// StatusNoPerms indicates that the capability is supported by the kernel but unavailable due to insufficient permissions.
	StatusNoPerms CapabilityStatus = "unavailable_permissions"
)

// RuntimeCapabilities represents a simplified boolean view of runtime capabilities available for workload execution.
type RuntimeCapabilities struct {
	UserNamespaces    bool `json:"user_namespaces"`
	UserNSMappings    bool `json:"userns_mappings"`
	MountNamespaces   bool `json:"mount_namespaces"`
	PIDNamespaces     bool `json:"pid_namespaces"`
	NetworkNamespaces bool `json:"network_namespaces"`
	IPCNamespaces     bool `json:"ipc_namespaces"`

	CgroupV2           bool `json:"cgroup_v2"`
	WritableCgroupTree bool `json:"writable_cgroup_tree"`

	Seccomp         bool `json:"seccomp"`
	NoNewPrivileges bool `json:"no_new_privileges"`

	ReadOnlyRootFS bool `json:"read_only_rootfs"`
}

// DetailedCapabilities provides granular status reporting (supported, unsupported, or permission denied) for each feature.
type DetailedCapabilities struct {
	UserNamespaces    CapabilityStatus `json:"user_namespaces"`
	UserNSMappings    CapabilityStatus `json:"userns_mappings"`
	MountNamespaces   CapabilityStatus `json:"mount_namespaces"`
	PIDNamespaces     CapabilityStatus `json:"pid_namespaces"`
	NetworkNamespaces CapabilityStatus `json:"network_namespaces"`
	IPCNamespaces     CapabilityStatus `json:"ipc_namespaces"`

	CgroupV2           CapabilityStatus `json:"cgroup_v2"`
	WritableCgroupTree CapabilityStatus `json:"writable_cgroup_tree"`

	Seccomp         CapabilityStatus `json:"seccomp"`
	NoNewPrivileges CapabilityStatus `json:"no_new_privileges"`

	ReadOnlyRootFS CapabilityStatus `json:"read_only_rootfs"`
}

// Detector defines the interface for probing runtime environment capabilities.
type Detector interface {
	Detect() (RuntimeCapabilities, DetailedCapabilities)
}

// Simplify converts a detailed capability report into a simplified boolean structure.
func (d DetailedCapabilities) Simplify() RuntimeCapabilities {
	return RuntimeCapabilities{
		UserNamespaces:     d.UserNamespaces == StatusSupported,
		UserNSMappings:     d.UserNSMappings == StatusSupported,
		MountNamespaces:    d.MountNamespaces == StatusSupported,
		PIDNamespaces:      d.PIDNamespaces == StatusSupported,
		NetworkNamespaces:  d.NetworkNamespaces == StatusSupported,
		IPCNamespaces:      d.IPCNamespaces == StatusSupported,
		CgroupV2:           d.CgroupV2 == StatusSupported,
		WritableCgroupTree: d.WritableCgroupTree == StatusSupported,
		Seccomp:            d.Seccomp == StatusSupported,
		NoNewPrivileges:    d.NoNewPrivileges == StatusSupported,
		ReadOnlyRootFS:     d.ReadOnlyRootFS == StatusSupported,
	}
}

// ToMap returns a key-value map representation of the detailed capabilities.
func (d DetailedCapabilities) ToMap() map[string]CapabilityStatus {
	return map[string]CapabilityStatus{
		"user_namespaces":      d.UserNamespaces,
		"userns_mappings":      d.UserNSMappings,
		"mount_namespaces":     d.MountNamespaces,
		"pid_namespaces":       d.PIDNamespaces,
		"network_namespaces":   d.NetworkNamespaces,
		"ipc_namespaces":       d.IPCNamespaces,
		"cgroup_v2":            d.CgroupV2,
		"writable_cgroup_tree": d.WritableCgroupTree,
		"seccomp":              d.Seccomp,
		"no_new_privileges":    d.NoNewPrivileges,
		"read_only_rootfs":     d.ReadOnlyRootFS,
	}
}

// FormatReport generates a human-readable summary of detected capabilities.
func (d DetailedCapabilities) FormatReport() string {
	m := d.ToMap()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("Runtime Capabilities Report:\n")
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  - %-22s : %s\n", k, m[k]))
	}
	return sb.String()
}

// Detect probes the current environment and returns both simplified and detailed capabilities.
func Detect() (RuntimeCapabilities, DetailedCapabilities) {
	return defaultDetector{}.Detect()
}

type defaultDetector struct{}

func (defaultDetector) Detect() (RuntimeCapabilities, DetailedCapabilities) {
	detailed := detectDetailed()
	return detailed.Simplify(), detailed
}
