package service

import (
	"errors"
	"slices"
	"testing"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

func TestAssessRuntimeFull(t *testing.T) {
	status := assessRuntime(fullRuntimeCapabilities(), nil, fullRuntimeHostChecks())

	if status.Level != RuntimeLevelFull {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelFull, status)
	}
	if status.Profile.Name != FullIsolationProfile || !hasFullIsolation(status.Profile.Features) {
		t.Fatalf("unexpected full profile: %#v", status.Profile)
	}
	if len(status.MissingForFull) != 0 || len(status.BlockingReasons) != 0 {
		t.Fatalf("full runtime has unexpected diagnostics: %#v", status)
	}
}

func TestAssessRuntimeLimitedWhenOptionalIsolationIsMissing(t *testing.T) {
	caps := fullRuntimeCapabilities()
	caps.CgroupV2 = false
	caps.WritableCgroupTree = false
	caps.Seccomp = false
	host := fullRuntimeHostChecks()
	host.effectiveCapabilities[12] = false

	status := assessRuntime(caps, nil, host)

	if status.Level != RuntimeLevelLimited {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelLimited, status)
	}
	if status.Profile.Features.Cgroups ||
		status.Profile.Features.Seccomp ||
		status.Profile.Features.NetworkNamespaces {
		t.Fatalf("limited profile enabled unavailable isolation: %#v", status.Profile.Features)
	}
	if !status.Profile.Features.MountNamespaces || !status.Profile.Features.NoNewPrivileges {
		t.Fatalf("limited profile lost minimum isolation: %#v", status.Profile.Features)
	}
	for _, missing := range []string{"cgroup resource isolation", "network namespaces", "seccomp"} {
		if !slices.Contains(status.MissingForFull, missing) {
			t.Errorf("missing_for_full does not contain %q: %#v", missing, status.MissingForFull)
		}
	}
}

func TestAssessRuntimeOmitsNetworkNamespaceWithoutSysPtrace(t *testing.T) {
	host := fullRuntimeHostChecks()
	host.effectiveCapabilities[19] = false

	status := assessRuntime(fullRuntimeCapabilities(), nil, host)

	if status.Level != RuntimeLevelLimited {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelLimited, status)
	}
	if status.Profile.Features.NetworkNamespaces {
		t.Fatal("limited profile enabled an unmanageable network namespace")
	}
	if !slices.Contains(status.MissingForFull, "network namespaces") {
		t.Fatalf("missing_for_full does not report network namespaces: %#v", status.MissingForFull)
	}
}

func TestAssessRuntimeOmitsNetworkNamespaceWhenSetnsIsBlocked(t *testing.T) {
	host := fullRuntimeHostChecks()
	host.networkNamespaceAccess = false

	status := assessRuntime(fullRuntimeCapabilities(), nil, host)

	if status.Level != RuntimeLevelLimited {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelLimited, status)
	}
	if status.Profile.Features.NetworkNamespaces {
		t.Fatal("limited profile enabled a network namespace when setns is blocked")
	}
	if !slices.Contains(status.MissingForFull, "network namespaces") {
		t.Fatalf("missing_for_full does not report network namespaces: %#v", status.MissingForFull)
	}
}

func TestAssessRuntimeUnisolatedWhenIsolationFloorIsMissing(t *testing.T) {
	caps := fullRuntimeCapabilities()
	caps.MountNamespaces = false

	status := assessRuntime(caps, nil, fullRuntimeHostChecks())

	if status.Level != RuntimeLevelUnisolated {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelUnisolated, status)
	}
	if !slices.Contains(status.MissingForLimited, "mount namespaces are unavailable") {
		t.Fatalf("unexpected limited-profile diagnostics: %#v", status.MissingForLimited)
	}
}

func TestAssessRuntimeRequiresProcessTreeControl(t *testing.T) {
	caps := fullRuntimeCapabilities()
	caps.PIDNamespaces = false
	caps.CgroupV2 = false
	caps.WritableCgroupTree = false

	status := assessRuntime(caps, nil, fullRuntimeHostChecks())

	if status.Level != RuntimeLevelUnisolated {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelUnisolated, status)
	}
	const reason = "workload process-tree control is unavailable (requires PID namespaces or cgroups)"
	if !slices.Contains(status.MissingForLimited, reason) {
		t.Fatalf("unexpected limited-profile diagnostics: %#v", status.MissingForLimited)
	}
}

func TestAssessRuntimeUnavailableWhenNeitherExecutorCanRun(t *testing.T) {
	caps := fullRuntimeCapabilities()
	caps.MountNamespaces = false
	host := fullRuntimeHostChecks()
	host.directExecutorAvailable = false
	host.directExecutorReason = "direct execution probe failed"

	status := assessRuntime(caps, nil, host)

	if status.Level != RuntimeLevelUnavailable {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelUnavailable, status)
	}
	for _, reason := range []string{"mount namespaces are unavailable", "direct execution probe failed"} {
		if !slices.Contains(status.BlockingReasons, reason) {
			t.Fatalf("blocking reasons do not contain %q: %#v", reason, status.BlockingReasons)
		}
	}
}

func TestAssessRuntimeUnavailableOnInitializationFailure(t *testing.T) {
	status := assessRuntime(
		fullRuntimeCapabilities(),
		errors.New("cannot secure runtime directory"),
		fullRuntimeHostChecks(),
	)

	if status.Level != RuntimeLevelUnavailable {
		t.Fatalf("runtime level = %q, want %q", status.Level, RuntimeLevelUnavailable)
	}
	if !slices.Contains(status.BlockingReasons, "cannot secure runtime directory") {
		t.Fatalf("unexpected blocking reasons: %#v", status.BlockingReasons)
	}
}

func TestAssessRuntimeUsesRootfulFallbackWithoutUserNamespaces(t *testing.T) {
	caps := fullRuntimeCapabilities()
	caps.UserNamespaces = false
	caps.UserNSMappings = false

	status := assessRuntime(caps, nil, fullRuntimeHostChecks())

	if status.Level != RuntimeLevelLimited {
		t.Fatalf("runtime level = %q, want %q: %#v", status.Level, RuntimeLevelLimited, status)
	}
	if status.Profile.Features.UserNamespaces {
		t.Fatal("rootful fallback unexpectedly enabled user namespaces")
	}
	if len(status.BlockingReasons) != 0 {
		t.Fatalf("rootful fallback was unexpectedly blocked: %#v", status.BlockingReasons)
	}
}

func TestNormalizeMinimumRuntimeLevelDefaultsToLimited(t *testing.T) {
	level, err := normalizeMinimumRuntimeLevel("")
	if err != nil {
		t.Fatalf("normalizeMinimumRuntimeLevel() error = %v", err)
	}
	if level != RuntimeLevelLimited {
		t.Fatalf("default minimum = %q, want %q", level, RuntimeLevelLimited)
	}
}

func TestRuntimeLevelOrdering(t *testing.T) {
	levels := []RuntimeLevel{
		RuntimeLevelUnavailable,
		RuntimeLevelUnisolated,
		RuntimeLevelLimited,
		RuntimeLevelFull,
	}
	for index, level := range levels {
		if rank := runtimeLevelRank(level); rank != index {
			t.Fatalf("rank(%q) = %d, want %d", level, rank, index)
		}
	}
}

func fullRuntimeCapabilities() capabilities.RuntimeCapabilities {
	return capabilities.RuntimeCapabilities{
		UserNamespaces:     true,
		UserNSMappings:     true,
		MountNamespaces:    true,
		PIDNamespaces:      true,
		NetworkNamespaces:  true,
		IPCNamespaces:      true,
		CgroupV2:           true,
		WritableCgroupTree: true,
		Seccomp:            true,
		NoNewPrivileges:    true,
		ReadOnlyRootFS:     true,
	}
}

func fullRuntimeHostChecks() runtimeHostChecks {
	effective := make(map[uint]bool, len(runtimeCapabilityRequirements))
	for _, capability := range runtimeCapabilityRequirements {
		effective[capability.bit] = true
	}
	return runtimeHostChecks{
		runcAvailable:              true,
		directExecutorAvailable:    true,
		effectiveCapabilities:      effective,
		userMappingsAvailable:      true,
		cgroupControllersAvailable: true,
		networkNamespaceAccess:     true,
	}
}
