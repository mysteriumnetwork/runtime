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

import "github.com/mysteriumnetwork/runtime/capabilities"

// Mount defines a filesystem mount or bind-mount specification for a workload container.
type Mount struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// Config specifies root filesystem setup, bind mounts, read-only rootfs rules, and future idmapped mounts.
type Config struct {
	RootPath   string  `json:"root_path"`
	ReadOnly   bool    `json:"read_only,omitempty"`
	BindMounts []Mount `json:"bind_mounts,omitempty"`
	IdMapped   bool    `json:"id_mapped,omitempty"`
}

// Manager defines the abstraction for preparing, isolating, and cleaning up workload filesystems.
type Manager interface {
	PrepareRootFS(id string, config Config, caps capabilities.RuntimeCapabilities) (string, error)
	CleanupRootFS(id string) error
}
