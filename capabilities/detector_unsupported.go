//go:build !linux && !windows

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

package capabilities

func detectDetailed() DetailedCapabilities {
	var detailed DetailedCapabilities

	// Linux-specific features are unsupported on non-Linux kernels
	detailed.UserNamespaces = StatusUnsupported
	detailed.UserNSMappings = StatusUnsupported
	detailed.MountNamespaces = StatusUnsupported
	detailed.PIDNamespaces = StatusUnsupported
	detailed.NetworkNamespaces = StatusUnsupported
	detailed.IPCNamespaces = StatusUnsupported

	detailed.CgroupV2 = StatusUnsupported
	detailed.WritableCgroupTree = StatusUnsupported

	detailed.Seccomp = StatusUnsupported
	detailed.NoNewPrivileges = StatusUnsupported

	detailed.ReadOnlyRootFS = StatusUnsupported

	return detailed
}
