package service

import (
	"sort"

	"github.com/mysteriumnetwork/runtime/capabilities"
	"github.com/pkg/errors"
)

type runtimeHostChecks struct {
	runcAvailable              bool
	directExecutorAvailable    bool
	directExecutorReason       string
	effectiveCapabilities      map[uint]bool
	userMappingsAvailable      bool
	cgroupControllersAvailable bool
}

var runtimeCapabilityRequirements = []struct {
	bit  uint
	name string
}{
	{0, "CAP_CHOWN"},
	{1, "CAP_DAC_OVERRIDE"},
	{3, "CAP_FOWNER"},
	{5, "CAP_KILL"},
	{6, "CAP_SETGID"},
	{7, "CAP_SETUID"},
	{12, "CAP_NET_ADMIN"},
	{18, "CAP_SYS_CHROOT"},
	{21, "CAP_SYS_ADMIN"},
	{27, "CAP_MKNOD"},
}

func assessRuntime(
	caps capabilities.RuntimeCapabilities,
	initErr error,
	host runtimeHostChecks,
) RuntimeStatus {
	isolatedFeatures := IsolationFeatures{
		FilesystemJail:      true,
		NonRootUser:         true,
		CapabilitiesDropped: true,
		UserNamespaces: caps.UserNamespaces &&
			caps.UserNSMappings &&
			host.userMappingsAvailable,
		MountNamespaces:   caps.MountNamespaces,
		PIDNamespaces:     caps.PIDNamespaces,
		NetworkNamespaces: caps.NetworkNamespaces && host.effectiveCapabilities[12],
		IPCNamespaces:     caps.IPCNamespaces,
		Cgroups: caps.CgroupV2 &&
			caps.WritableCgroupTree &&
			host.cgroupControllersAvailable,
		Seccomp:         caps.Seccomp,
		NoNewPrivileges: caps.NoNewPrivileges,
		ReadOnlyRootFS:  caps.ReadOnlyRootFS,
	}
	status := RuntimeStatus{
		FullProfile:       FullIsolationProfile,
		LimitedProfile:    BestEffortIsolationProfile,
		UnisolatedProfile: UnisolatedProfile,
		Profile: IsolationProfile{
			Name:  UnisolatedProfile,
			Level: RuntimeLevelUnavailable,
			Features: IsolationFeatures{
				FilesystemJail:      true,
				NonRootUser:         true,
				CapabilitiesDropped: true,
				NoNewPrivileges:     caps.NoNewPrivileges,
			},
		},
	}

	fullRequirements := []struct {
		name string
		ok   bool
	}{
		{"user namespaces", isolatedFeatures.UserNamespaces},
		{"mount namespaces", isolatedFeatures.MountNamespaces},
		{"PID namespaces", isolatedFeatures.PIDNamespaces},
		{"network namespaces", isolatedFeatures.NetworkNamespaces},
		{"IPC namespaces", isolatedFeatures.IPCNamespaces},
		{"cgroup resource isolation", isolatedFeatures.Cgroups},
		{"seccomp", isolatedFeatures.Seccomp},
		{"no_new_privileges", isolatedFeatures.NoNewPrivileges},
		{"read-only rootfs", isolatedFeatures.ReadOnlyRootFS},
	}
	for _, requirement := range fullRequirements {
		if !requirement.ok {
			status.MissingForFull = append(status.MissingForFull, requirement.name)
		}
	}

	var isolatedMissing []string
	if initErr != nil {
		status.BlockingReasons = append(status.BlockingReasons, initErr.Error())
	}
	if !host.runcAvailable {
		isolatedMissing = append(isolatedMissing, "runc executable is unavailable")
	}
	if !isolatedFeatures.MountNamespaces {
		isolatedMissing = append(isolatedMissing, "mount namespaces are unavailable")
	}
	if !isolatedFeatures.NoNewPrivileges {
		isolatedMissing = append(isolatedMissing, "no_new_privileges is unavailable")
	}
	if !isolatedFeatures.PIDNamespaces && !isolatedFeatures.Cgroups {
		isolatedMissing = append(
			isolatedMissing,
			"workload process-tree control is unavailable (requires PID namespaces or cgroups)",
		)
	}

	var directMissing []string
	if !host.directExecutorAvailable {
		reason := host.directExecutorReason
		if reason == "" {
			reason = "built-in direct executor is unavailable"
		}
		directMissing = append(directMissing, reason)
	}
	// These capabilities are required by rootfs extraction and process setup
	// for both execution engines.
	for _, bit := range []uint{0, 1, 3, 5, 6, 7, 18} {
		if !host.effectiveCapabilities[bit] {
			reason := effectiveCapabilityName(bit) + " is unavailable"
			isolatedMissing = append(isolatedMissing, reason)
			directMissing = append(directMissing, reason)
		}
	}
	// User namespaces provide namespaced mount and device capabilities. A
	// rootful fallback needs their host equivalents.
	if !isolatedFeatures.UserNamespaces {
		for _, bit := range []uint{21, 27} {
			if !host.effectiveCapabilities[bit] {
				isolatedMissing = append(
					isolatedMissing,
					effectiveCapabilityName(bit)+" is unavailable without user namespaces",
				)
			}
		}
	}

	status.MissingForFull = uniqueSorted(status.MissingForFull)
	isolatedMissing = uniqueSorted(isolatedMissing)
	directMissing = uniqueSorted(directMissing)
	status.BlockingReasons = uniqueSorted(status.BlockingReasons)

	if len(status.BlockingReasons) > 0 {
		status.Level = RuntimeLevelUnavailable
		return status
	}
	if len(isolatedMissing) > 0 {
		if len(directMissing) == 0 {
			status.Level = RuntimeLevelUnisolated
			status.Profile.Level = RuntimeLevelUnisolated
			status.MissingForLimited = isolatedMissing
			return status
		}
		status.BlockingReasons = uniqueSorted(append(isolatedMissing, directMissing...))
		status.Level = RuntimeLevelUnavailable
		return status
	}
	if len(status.MissingForFull) > 0 {
		status.Level = RuntimeLevelLimited
		status.Profile.Name = BestEffortIsolationProfile
		status.Profile.Level = RuntimeLevelLimited
		status.Profile.Features = isolatedFeatures
		return status
	}

	status.Level = RuntimeLevelFull
	status.Profile.Name = FullIsolationProfile
	status.Profile.Level = RuntimeLevelFull
	status.Profile.Features = isolatedFeatures
	return status
}

func normalizeMinimumRuntimeLevel(level RuntimeLevel) (RuntimeLevel, error) {
	if level == "" {
		return RuntimeLevelLimited, nil
	}
	switch level {
	case RuntimeLevelUnisolated, RuntimeLevelLimited, RuntimeLevelFull:
		return level, nil
	default:
		return "", errors.Errorf("invalid minimum runtime level %q", level)
	}
}

func runtimeLevelRank(level RuntimeLevel) int {
	switch level {
	case RuntimeLevelUnavailable:
		return 0
	case RuntimeLevelUnisolated:
		return 1
	case RuntimeLevelLimited:
		return 2
	case RuntimeLevelFull:
		return 3
	default:
		return -1
	}
}

func effectiveCapabilityName(bit uint) string {
	for _, capability := range runtimeCapabilityRequirements {
		if capability.bit == bit {
			return capability.name
		}
	}
	return "unknown effective capability"
}

func hasFullIsolation(features IsolationFeatures) bool {
	return features.FilesystemJail &&
		features.NonRootUser &&
		features.CapabilitiesDropped &&
		features.UserNamespaces &&
		features.MountNamespaces &&
		features.PIDNamespaces &&
		features.NetworkNamespaces &&
		features.IPCNamespaces &&
		features.Cgroups &&
		features.Seccomp &&
		features.NoNewPrivileges &&
		features.ReadOnlyRootFS
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloneRuntimeStatus(status RuntimeStatus) RuntimeStatus {
	status.MissingForLimited = append([]string(nil), status.MissingForLimited...)
	status.MissingForFull = append([]string(nil), status.MissingForFull...)
	status.BlockingReasons = append([]string(nil), status.BlockingReasons...)
	return status
}
