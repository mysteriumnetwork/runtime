//go:build linux

package capabilities

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseUnifiedCgroupPath(t *testing.T) {
	tests := []struct {
		name string
		data string
		path string
		ok   bool
	}{
		{
			name: "container namespace root",
			data: "0::/\n",
			path: "/",
			ok:   true,
		},
		{
			name: "system service",
			data: "0::/system.slice/mysterium-node.service\n",
			path: "/system.slice/mysterium-node.service",
			ok:   true,
		},
		{
			name: "no unified hierarchy",
			data: "2:cpu:/legacy\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, ok := parseUnifiedCgroupPath(test.data)
			if ok != test.ok || path != test.path {
				t.Fatalf("parseUnifiedCgroupPath() = (%q, %v), want (%q, %v)", path, ok, test.path, test.ok)
			}
		})
	}
}

func TestIsDelegatedUnifiedCgroupPath(t *testing.T) {
	if isDelegatedUnifiedCgroupPath("/") {
		t.Fatal("cgroup namespace root must not be treated as delegated")
	}
	if !isDelegatedUnifiedCgroupPath("/system.slice/mysterium-node.service") {
		t.Fatal("non-root service cgroup should be treated as delegated")
	}
}

func TestNamespaceProbeConfiguration(t *testing.T) {
	flags, operation, ok := namespaceProbeConfiguration("user")
	if !ok {
		t.Fatal("user namespace probe configuration is missing")
	}
	required := uintptr(
		unix.CLONE_NEWUSER |
			unix.CLONE_NEWNS |
			unix.CLONE_NEWPID |
			unix.CLONE_NEWNET |
			unix.CLONE_NEWIPC |
			unix.CLONE_NEWUTS,
	)
	if flags&required != required {
		t.Fatalf("user namespace probe flags %#x do not contain %#x", flags, required)
	}
	if operation != namespaceProbeMountProc {
		t.Fatalf("user namespace probe operation = %q, want %q", operation, namespaceProbeMountProc)
	}

	if _, _, ok := namespaceProbeConfiguration("unknown"); ok {
		t.Fatal("unknown namespace unexpectedly has a probe configuration")
	}
}

func TestClassifyNamespaceProbeError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status CapabilityStatus
	}{
		{name: "success", status: StatusSupported},
		{name: "permission", err: unix.EPERM, status: StatusNoPerms},
		{name: "read only", err: unix.EROFS, status: StatusNoPerms},
		{name: "unsupported", err: unix.EOPNOTSUPP, status: StatusUnsupported},
		{name: "unknown fails closed", err: errors.New("probe failed"), status: StatusUnsupported},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if status := classifyNamespaceProbeError(test.err); status != test.status {
				t.Fatalf("classifyNamespaceProbeError(%v) = %q, want %q", test.err, status, test.status)
			}
		})
	}
}

func TestFindSubIDRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	data := []byte("# ignored\nother:1000:10\nruntime:100000:65536\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	idRange, status := findSubIDRange(path, "runtime", "123")
	if status != StatusSupported {
		t.Fatalf("findSubIDRange() status = %q, want %q", status, StatusSupported)
	}
	if idRange.hostID != 100000 || idRange.size != 65536 {
		t.Fatalf("findSubIDRange() = %#v, want host ID 100000 and size 65536", idRange)
	}
}

func TestFindSubIDRangeRejectsOverflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	if err := os.WriteFile(path, []byte("runtime:4294967295:2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, status := findSubIDRange(path, "runtime", "123"); status != StatusUnsupported {
		t.Fatalf("findSubIDRange() status = %q, want %q", status, StatusUnsupported)
	}
}

func TestFindSubIDRangeRejectsShortRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	if err := os.WriteFile(path, []byte("runtime:100000:65535\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, status := findSubIDRange(path, "runtime", "123"); status != StatusUnsupported {
		t.Fatalf("findSubIDRange() status = %q, want %q", status, StatusUnsupported)
	}
}
