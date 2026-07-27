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

import "github.com/mysteriumnetwork/runtime/capabilities"

// NamespaceType identifies a specific Linux kernel namespace type.
type NamespaceType string

const (
	UserNamespace    NamespaceType = "user"
	MountNamespace   NamespaceType = "mnt"
	PIDNamespace     NamespaceType = "pid"
	NetworkNamespace NamespaceType = "net"
	IPCNamespace     NamespaceType = "ipc"
	UTSNamespace     NamespaceType = "uts"
)

// Config specifies the desired namespace isolation topology for a workload.
type Config struct {
	User    bool `json:"user,omitempty"`
	Mount   bool `json:"mount,omitempty"`
	PID     bool `json:"pid,omitempty"`
	Network bool `json:"network,omitempty"`
	IPC     bool `json:"ipc,omitempty"`
	UTS     bool `json:"uts,omitempty"`
}

// Manager defines the abstraction for creating, configuring, and applying Linux namespace isolation.
type Manager interface {
	Configure(id string, config Config, caps capabilities.RuntimeCapabilities) error
	Apply(pid int, caps capabilities.RuntimeCapabilities) error
}
