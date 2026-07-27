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

// ResourceLimits describe quantitative runtime resource constraints for workloads without exposing cgroup-specific concepts.
type ResourceLimits struct {
	MemoryBytes uint64  `json:"memory_bytes,omitempty"`
	CPUQuota    float64 `json:"cpu_quota,omitempty"`
	Pids        uint32  `json:"pids,omitempty"`
}

// ResourceLimiter defines the abstraction for managing resource constraints and attaching process trees.
type ResourceLimiter interface {
	Create(id string, limits ResourceLimits) error
	Attach(pid int) error
	Destroy(id string) error
}

// IDAttacher is an optional interface implemented by resource limiters that support attaching a process to a specific workload ID.
type IDAttacher interface {
	AttachID(id string, pid int) error
}
