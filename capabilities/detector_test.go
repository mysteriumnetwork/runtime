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

import (
	"strings"
	"testing"
)

func TestDetectAndSimplify(t *testing.T) {
	simple, detailed := Detect()

	// Verify simplify consistency
	if simple.UserNamespaces != (detailed.UserNamespaces == StatusSupported) {
		t.Errorf("UserNamespaces mismatch between simplified (%v) and detailed (%v)", simple.UserNamespaces, detailed.UserNamespaces)
	}
	if simple.UserNSMappings != (detailed.UserNSMappings == StatusSupported) {
		t.Errorf("UserNSMappings mismatch between simplified (%v) and detailed (%v)", simple.UserNSMappings, detailed.UserNSMappings)
	}
	if simple.CgroupV2 != (detailed.CgroupV2 == StatusSupported) {
		t.Errorf("CgroupV2 mismatch between simplified (%v) and detailed (%v)", simple.CgroupV2, detailed.CgroupV2)
	}
	if simple.WritableCgroupTree != (detailed.WritableCgroupTree == StatusSupported) {
		t.Errorf("WritableCgroupTree mismatch between simplified (%v) and detailed (%v)", simple.WritableCgroupTree, detailed.WritableCgroupTree)
	}
	if simple.Seccomp != (detailed.Seccomp == StatusSupported) {
		t.Errorf("Seccomp mismatch between simplified (%v) and detailed (%v)", simple.Seccomp, detailed.Seccomp)
	}
}

func TestDetailedCapabilities_FormatReport(t *testing.T) {
	detailed := DetailedCapabilities{
		UserNamespaces:     StatusSupported,
		UserNSMappings:     StatusSupported,
		MountNamespaces:    StatusUnsupported,
		PIDNamespaces:      StatusNoPerms,
		NetworkNamespaces:  StatusSupported,
		IPCNamespaces:      StatusSupported,
		CgroupV2:           StatusSupported,
		WritableCgroupTree: StatusNoPerms,
		Seccomp:            StatusSupported,
		NoNewPrivileges:    StatusSupported,
		ReadOnlyRootFS:     StatusSupported,
	}

	report := detailed.FormatReport()
	if !strings.Contains(report, "user_namespaces") || !strings.Contains(report, "supported") {
		t.Errorf("FormatReport missing expected strings: %s", report)
	}
	if !strings.Contains(report, "pid_namespaces") || !strings.Contains(report, "unavailable_permissions") {
		t.Errorf("FormatReport missing unavailable_permissions: %s", report)
	}

	m := detailed.ToMap()
	if len(m) != 11 {
		t.Errorf("expected 11 capability keys in ToMap, got %d", len(m))
	}
}
