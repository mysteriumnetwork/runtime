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

package network

import (
	"sync"

	"github.com/pkg/errors"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

// DefaultManager is a skeleton implementation for workload network isolation.
// It decouples network setup from container runtime lifecycle and serves as an extension point
// for custom network namespace providers, CNI plugins, and port-forwarding iptables rules.
type DefaultManager struct {
	mu       sync.Mutex
	networks map[string]Config
}

// NewManager creates a new default network isolation manager.
func NewManager() *DefaultManager {
	return &DefaultManager{
		networks: make(map[string]Config),
	}
}

// Setup validates the network configuration against host capabilities and registers network state.
func (m *DefaultManager) Setup(id string, config Config, caps capabilities.RuntimeCapabilities) error {
	if id == "" {
		return errors.New("network: workload id is required")
	}

	if (config.Mode == ModeBridge || config.Mode == ModeNone || config.Mode == ModeCustom) && !caps.NetworkNamespaces {
		return errors.Errorf("network mode %q requested but network namespaces are not supported by host", config.Mode)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.networks[id] = config
	return nil
}

// Teardown cleans up network state and releases any allocated interfaces or rules for the workload.
func (m *DefaultManager) Teardown(id string) error {
	if id == "" {
		return errors.New("network: workload id is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.networks, id)
	return nil
}
