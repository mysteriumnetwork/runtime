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

package resources

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

func TestFactorySelection(t *testing.T) {
	cgroupCaps := capabilities.RuntimeCapabilities{CgroupV2: true, WritableCgroupTree: true}
	limiter := NewResourceLimiter(cgroupCaps)
	if _, ok := limiter.(*CgroupLimiter); !ok {
		t.Fatalf("expected CgroupLimiter when cgroup v2 is writable, got %T", limiter)
	}

	noCgroupCaps := capabilities.RuntimeCapabilities{WritableCgroupTree: false}
	limiter = NewResourceLimiter(noCgroupCaps)
	if _, ok := limiter.(*NoopLimiter); !ok {
		t.Fatalf("expected NoopLimiter without cgroup capability, got %T", limiter)
	}
}

func TestNoopLimiterLifecycle(t *testing.T) {
	limiter := &NoopLimiter{}
	if err := limiter.Create("test", ResourceLimits{MemoryBytes: 1}); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Attach(1); err != nil {
		t.Fatal(err)
	}
	if err := limiter.AttachID("test", 1); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Destroy("test"); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupLimiter_Lifecycle(t *testing.T) {
	tempRoot := filepath.Join(t.TempDir(), "cgroup-test")
	limiter := NewCgroupLimiterWithRoot(tempRoot)
	limits := ResourceLimits{
		MemoryBytes: 1024 * 1024 * 128,
		CPUQuota:    0.5,
		Pids:        100,
	}

	err := limiter.Create("test-cg", limits)
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatalf("expected error on non-linux systems for cgroups, got nil")
		}
		return
	}

	if err != nil {
		t.Fatalf("failed to create cgroup in temp root: %v", err)
	}

	// Verify limit files created
	cgDir := filepath.Join(tempRoot, "test-cg")
	if _, err := os.Stat(filepath.Join(cgDir, "memory.max")); err != nil {
		t.Errorf("memory.max not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cgDir, "cpu.max")); err != nil {
		t.Errorf("cpu.max not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cgDir, "pids.max")); err != nil {
		t.Errorf("pids.max not created: %v", err)
	}

	if err := limiter.AttachID("test-cg", os.Getpid()); err != nil {
		t.Fatalf("failed to attach to cgroup: %v", err)
	}

	if err := limiter.Destroy("test-cg"); err != nil {
		t.Fatalf("failed to destroy cgroup: %v", err)
	}
	if _, err := os.Stat(cgDir); !os.IsNotExist(err) {
		t.Errorf("expected cgroup dir to be removed after destroy, stat err: %v", err)
	}
}
