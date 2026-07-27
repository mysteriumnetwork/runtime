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

package security

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

// DefaultManager is a skeleton implementation for workload security policy enforcement.
// It serves as an extension point for seccomp BPF filtering, Landlock unprivileged filesystem sandboxing,
// Linux capability drop/retain rules, and rootless user namespace execution.
type DefaultManager struct {
	mu      sync.Mutex
	configs map[string]Config
}

// NewManager creates a new default security manager.
func NewManager() *DefaultManager {
	return &DefaultManager{
		configs: make(map[string]Config),
	}
}

// ConfigureSecurity validates security requirements against detected host capabilities and registers security policies.
func (m *DefaultManager) ConfigureSecurity(id string, config Config, caps capabilities.RuntimeCapabilities) error {
	if id == "" {
		return errors.New("security: workload id is required")
	}
	if config.NoNewPrivileges && !caps.NoNewPrivileges {
		return errors.New("no_new_privs requested but not supported by host environment")
	}
	if config.SeccompProfile != "" && !caps.Seccomp {
		return errors.New("seccomp profile requested but seccomp is not supported by host environment")
	}
	if config.Rootless && !caps.UserNamespaces {
		return errors.New("rootless execution requested but user namespaces are not supported by host environment")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[id] = config
	return nil
}
