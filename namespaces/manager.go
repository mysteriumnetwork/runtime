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

package namespaces

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

// DefaultManager is a skeleton implementation of namespace isolation management.
// It decouples namespace topology decisions from OCI bundle execution and allows
// automatic adaptation when unprivileged user namespaces or specific kernel features are missing.
type DefaultManager struct {
	mu      sync.Mutex
	configs map[string]Config
}

// NewManager creates a new default namespace manager.
func NewManager() *DefaultManager {
	return &DefaultManager{
		configs: make(map[string]Config),
	}
}

// Configure validates requested namespaces against detected host capabilities and stores the configuration.
func (m *DefaultManager) Configure(id string, config Config, caps capabilities.RuntimeCapabilities) error {
	if id == "" {
		return errors.New("namespaces: workload id is required")
	}

	// Validate requested namespace isolation against host capabilities
	if config.User && !caps.UserNamespaces {
		return errors.New("user namespaces requested but not supported or permitted by host")
	}
	if config.Mount && !caps.MountNamespaces {
		return errors.New("mount namespaces requested but not supported by host")
	}
	if config.PID && !caps.PIDNamespaces {
		return errors.New("pid namespaces requested but not supported by host")
	}
	if config.Network && !caps.NetworkNamespaces {
		return errors.New("network namespaces requested but not supported by host")
	}
	if config.IPC && !caps.IPCNamespaces {
		return errors.New("ipc namespaces requested but not supported by host")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[id] = config
	return nil
}

// Apply joins or initializes namespace isolation for the specified target process PID.
// In the current skeleton, actual namespace cloning is performed by the OCI runtime (runc),
// while this method serves as an extension point for standalone execution or custom namespace joining (setns).
func (m *DefaultManager) Apply(pid int, caps capabilities.RuntimeCapabilities) error {
	if pid <= 0 {
		return errors.New("namespaces: valid target pid required")
	}
	return nil
}
