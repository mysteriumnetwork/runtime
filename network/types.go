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

import "github.com/mysteriumnetwork/runtime/capabilities"

// NetworkMode defines the isolation mode for workload networking.
type NetworkMode string

const (
	ModeHost   NetworkMode = "host"
	ModeBridge NetworkMode = "bridge"
	ModeNone   NetworkMode = "none"
	ModeCustom NetworkMode = "custom"
)

// PortMapping defines host-to-container port forwarding.
type PortMapping struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol,omitempty"` // tcp, udp
}

// Config specifies workload network topology, bridge devices, port mappings, and custom network namespace providers.
type Config struct {
	Mode           NetworkMode   `json:"mode"`
	BridgeName     string        `json:"bridge_name,omitempty"`
	PortMappings   []PortMapping `json:"port_mappings,omitempty"`
	CustomProvider string        `json:"custom_provider,omitempty"`
}

// Manager defines the abstraction for configuring and tearing down container network interfaces and namespaces.
type Manager interface {
	Setup(id string, config Config, caps capabilities.RuntimeCapabilities) error
	Teardown(id string) error
}
