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

package resources

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

const (
	defaultCgroupRoot = "/sys/fs/cgroup/mysterium"
	defaultCPUPeriod  = int64(100000)
)

// CgroupLimiter manages Linux resource isolation using cgroup v2 hierarchies.
type CgroupLimiter struct {
	mu       sync.Mutex
	rootPath string
	cgroups  map[string]string
	lastID   string
}

// NewCgroupLimiter initializes a CgroupLimiter at the default cgroup v2 root path.
func NewCgroupLimiter() *CgroupLimiter {
	return NewCgroupLimiterWithRoot(defaultCgroupRoot)
}

// NewCgroupLimiterWithRoot initializes a CgroupLimiter with a custom root path (useful for testing).
func NewCgroupLimiterWithRoot(rootPath string) *CgroupLimiter {
	return &CgroupLimiter{
		rootPath: rootPath,
		cgroups:  make(map[string]string),
	}
}

// Create generates a new cgroup v2 directory for the workload and configures resource limits.
func (l *CgroupLimiter) Create(id string, limits ResourceLimits) error {
	if id == "" {
		return errors.New("resource limiter: id is required")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(l.rootPath, 0o755); err != nil {
		return errors.Wrapf(err, "failed to create cgroup root directory %q", l.rootPath)
	}

	enableSubtreeControl(filepath.Dir(l.rootPath))
	enableSubtreeControl(l.rootPath)

	dir := filepath.Join(l.rootPath, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.Wrapf(err, "failed to create cgroup directory for %q", id)
	}

	if limits.MemoryBytes > 0 {
		memFile := filepath.Join(dir, "memory.max")
		val := strconv.FormatUint(limits.MemoryBytes, 10)
		if err := os.WriteFile(memFile, []byte(val), 0o644); err != nil {
			return errors.Wrapf(err, "failed to set cgroup memory limit for %q", id)
		}
	}

	if limits.CPUQuota > 0 {
		cpuFile := filepath.Join(dir, "cpu.max")
		quota := int64(math.Round(limits.CPUQuota * float64(defaultCPUPeriod)))
		if quota < 1000 {
			quota = 1000
		}
		val := fmt.Sprintf("%d %d", quota, defaultCPUPeriod)
		if err := os.WriteFile(cpuFile, []byte(val), 0o644); err != nil {
			return errors.Wrapf(err, "failed to set cgroup cpu limit for %q", id)
		}
	}

	if limits.Pids > 0 {
		pidsFile := filepath.Join(dir, "pids.max")
		val := strconv.FormatUint(uint64(limits.Pids), 10)
		if err := os.WriteFile(pidsFile, []byte(val), 0o644); err != nil {
			return errors.Wrapf(err, "failed to set cgroup pids limit for %q", id)
		}
	}

	l.cgroups[id] = dir
	l.lastID = id
	return nil
}

// Attach adds the specified process PID to the last created or active cgroup.
func (l *CgroupLimiter) Attach(pid int) error {
	l.mu.Lock()
	targetID := l.lastID
	if targetID == "" && len(l.cgroups) == 1 {
		for id := range l.cgroups {
			targetID = id
			break
		}
	}
	l.mu.Unlock()

	if targetID == "" {
		return errors.New("cgroup limiter: no cgroup created yet to attach pid")
	}
	return l.AttachID(targetID, pid)
}

// AttachID adds the specified process PID to the cgroup identified by id.
func (l *CgroupLimiter) AttachID(id string, pid int) error {
	l.mu.Lock()
	dir, ok := l.cgroups[id]
	l.mu.Unlock()
	if !ok {
		return errors.Errorf("cgroup limiter: cgroup %q not found", id)
	}

	procsPath := filepath.Join(dir, "cgroup.procs")
	if err := os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return errors.Wrapf(err, "failed to attach pid %d to cgroup %q", pid, id)
	}
	return nil
}

// Destroy removes the cgroup directory for the specified workload ID.
func (l *CgroupLimiter) Destroy(id string) error {
	if id == "" {
		return errors.New("resource limiter: id is required")
	}

	l.mu.Lock()
	dir, ok := l.cgroups[id]
	if ok {
		delete(l.cgroups, id)
		if l.lastID == id {
			l.lastID = ""
			for k := range l.cgroups {
				l.lastID = k
				break
			}
		}
	}
	l.mu.Unlock()

	if !ok {
		return nil
	}

	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to destroy cgroup %q", id)
	}
	return nil
}

func enableSubtreeControl(dir string) {
	controllersPath := filepath.Join(dir, "cgroup.controllers")
	controllersData, err := os.ReadFile(controllersPath)
	if err != nil {
		return
	}
	controllers := strings.Fields(string(controllersData))
	if len(controllers) == 0 {
		return
	}

	// Move current processes out of directory if necessary for leaf node requirement in cgroup v2
	procsPath := filepath.Join(dir, "cgroup.procs")
	procsData, err := os.ReadFile(procsPath)
	if err == nil && len(bytes.TrimSpace(procsData)) > 0 {
		leafDir := filepath.Join(dir, "supervisor")
		if err := os.MkdirAll(leafDir, 0o755); err == nil {
			leafProcsPath := filepath.Join(leafDir, "cgroup.procs")
			for _, pid := range bytes.Split(procsData, []byte{'\n'}) {
				pid = bytes.TrimSpace(pid)
				if len(pid) > 0 {
					_ = os.WriteFile(leafProcsPath, pid, 0o644)
				}
			}
		}
	}

	var toEnable []string
	for _, ctrl := range controllers {
		toEnable = append(toEnable, "+"+ctrl)
	}
	if len(toEnable) > 0 {
		subtreePath := filepath.Join(dir, "cgroup.subtree_control")
		if err := os.WriteFile(subtreePath, []byte(strings.Join(toEnable, " ")), 0o644); err != nil {
			for _, ctrl := range toEnable {
				_ = os.WriteFile(subtreePath, []byte(ctrl), 0o644)
			}
		}
	}
}
