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

import "github.com/mysteriumnetwork/runtime/capabilities"

// NewResourceLimiter returns the cgroup v2 resource limiter used for runtime
// workloads. The limiter will fail closed if the host does not provide a
// writable delegated cgroup tree.
func NewResourceLimiter(c capabilities.RuntimeCapabilities) ResourceLimiter {
	return NewCgroupLimiter()
}
