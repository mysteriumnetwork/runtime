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

package filesystem

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

// DefaultManager is a skeleton implementation for filesystem isolation and rootfs lifecycle management.
// It serves as an extension point for advanced filesystem mechanisms such as idmapped mounts (Linux 5.12+),
// overlayfs rootless mounting, and read-only rootfs enforcement.
type DefaultManager struct {
	mu      sync.Mutex
	mounts  map[string]Config
	baseDir string
}

// NewManager creates a new default filesystem isolation manager.
func NewManager(baseDir string) *DefaultManager {
	return &DefaultManager{
		mounts:  make(map[string]Config),
		baseDir: baseDir,
	}
}

// PrepareRootFS initializes the target root filesystem directory and validates requested isolation parameters.
func (m *DefaultManager) PrepareRootFS(id string, config Config, caps capabilities.RuntimeCapabilities) (string, error) {
	if id == "" {
		return "", errors.New("filesystem: workload id is required")
	}
	if config.ReadOnly && !caps.ReadOnlyRootFS {
		return "", errors.New("read-only rootfs requested but not supported by host environment")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	targetPath := config.RootPath
	if targetPath == "" && m.baseDir != "" {
		targetPath = filepath.Join(m.baseDir, id, "rootfs")
	}
	if targetPath == "" {
		return "", errors.New("filesystem: root_path or manager base_dir is required")
	}

	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		return "", errors.Wrapf(err, "failed to create rootfs directory %q for workload %q", targetPath, id)
	}

	m.mounts[id] = config
	return targetPath, nil
}

// CleanupRootFS removes tracked filesystem mount state and cleans up temporary rootfs directories if applicable.
func (m *DefaultManager) CleanupRootFS(id string) error {
	if id == "" {
		return errors.New("filesystem: workload id is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.mounts, id)
	return nil
}
