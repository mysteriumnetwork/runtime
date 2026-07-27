//go:build linux

package capabilities

import "testing"

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
