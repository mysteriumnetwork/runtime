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

import "github.com/mysteriumnetwork/runtime/capabilities"

// Config specifies security restrictions, capabilities, seccomp profiles, and future Landlock sandbox rules.
type Config struct {
	NoNewPrivileges bool     `json:"no_new_privileges,omitempty"`
	SeccompProfile  string   `json:"seccomp_profile,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Rootless        bool     `json:"rootless,omitempty"`
	Landlock        bool     `json:"landlock,omitempty"`
}

// Manager defines the abstraction for applying kernel security restrictions to workloads.
type Manager interface {
	ConfigureSecurity(id string, config Config, caps capabilities.RuntimeCapabilities) error
}
