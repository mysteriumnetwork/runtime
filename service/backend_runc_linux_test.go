//go:build linux

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

package service

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestProcessFromImagePreservesOCIArguments(t *testing.T) {
	process, err := processFromImage(&v1.ConfigFile{Config: v1.Config{
		Entrypoint: []string{"/usr/bin/server", "--label", "value with spaces"},
		Cmd:        []string{"serve"},
		Env:        []string{"A=value with spaces"},
		WorkingDir: "/app",
		User:       "1000:1001",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(process.Args) != 4 || process.Args[2] != "value with spaces" {
		t.Fatalf("OCI argument boundaries were changed: %#v", process.Args)
	}
	if process.UID != 1000 || process.GID != 1001 || process.Cwd != "/app" {
		t.Fatalf("OCI process metadata was not preserved: %#v", process)
	}
}

func TestProcessFromImageRejectsRootUser(t *testing.T) {
	_, err := processFromImage(&v1.ConfigFile{Config: v1.Config{
		Entrypoint: []string{"/bin/server"},
		User:       "0",
	}})
	if err == nil {
		t.Fatal("expected root image user to be rejected")
	}
}

func TestValidateManifestAppliesMandatoryDefaults(t *testing.T) {
	var manifest Manifest
	manifest.SchemaVersion = 1
	manifest.Service.Protocol = "tcp"
	manifest.Service.InternalPort = 8080
	limits, err := validateManifest(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limits.CPU == "" || limits.Memory == "" || limits.Disk == "" || limits.Pids == 0 {
		t.Fatalf("mandatory resource defaults were not applied: %#v", limits)
	}
	resources := buildLinuxResources(limits)
	if resources == nil || resources.CPU == nil || resources.Memory == nil || resources.Pids == nil {
		t.Fatalf("mandatory OCI resource controls were not generated: %#v", resources)
	}
	if len(resources.Unified) != 0 {
		t.Fatalf("unexpected fake cgroup controls: %#v", resources.Unified)
	}
}

func TestValidateManifestRejectsUDP(t *testing.T) {
	var manifest Manifest
	manifest.SchemaVersion = 1
	manifest.Service.Protocol = "udp"
	manifest.Service.InternalPort = 8080
	if _, err := validateManifest(manifest); err == nil {
		t.Fatal("expected UDP runtime service to be rejected")
	}
}

func TestValidateStoredOptionsRejectsLegacyMutableDefinition(t *testing.T) {
	err := validateStoredOptions(Options{
		Name:        "runtime.legacy",
		OCIArtifact: "example.invalid/legacy:latest",
	})
	if err == nil {
		t.Fatal("expected legacy mutable runtime definition to be rejected")
	}
}

func TestValidateServiceName(t *testing.T) {
	valid := []string{"svc1", "service.alpha-1_2", "A1"}
	for _, name := range valid {
		if err := validateServiceName(name); err != nil {
			t.Fatalf("expected name %q to be valid, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		" ",
		".",
		"..",
		"/etc/passwd",
		"svc/name",
		"svc name",
		"-svc",
		"_svc",
		strings.Repeat("a", maxServiceNameLength+1),
	}
	for _, name := range invalid {
		if err := validateServiceName(name); err == nil {
			t.Fatalf("expected name %q to be invalid", name)
		}
	}
}

func TestSecureJoinUnder(t *testing.T) {
	root := t.TempDir()

	path, err := secureJoinUnder(root, "bin/sh")
	if err != nil {
		t.Fatalf("expected valid entry path, got error: %v", err)
	}
	if !isPathWithinRoot(root, path) {
		t.Fatalf("expected path %q to stay under root %q", path, root)
	}

	if _, err := secureJoinUnder(root, "../etc/passwd"); err == nil {
		t.Fatal("expected traversal path to be rejected")
	}

	if _, err := secureJoinUnder(root, "/etc/passwd"); err == nil {
		t.Fatal("expected absolute path to be rejected")
	}
}

func TestSecureSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	linkPath := filepath.Join(root, "usr", "bin", "tool")

	target, err := secureSymlinkTarget(root, linkPath, "../lib/tool")
	if err != nil {
		t.Fatalf("expected in-root symlink target to be valid, got error: %v", err)
	}
	if target != filepath.FromSlash("../lib/tool") {
		t.Fatalf("expected relative symlink target to remain unchanged, got %q", target)
	}

	if _, err := secureSymlinkTarget(root, linkPath, "../../../../etc/shadow"); err == nil {
		t.Fatal("expected escaping symlink target to be rejected")
	}

	target, err = secureSymlinkTarget(root, linkPath, "/bin/busybox")
	if err != nil {
		t.Fatalf("expected absolute in-container symlink target to be valid, got error: %v", err)
	}
	if target != filepath.Join("..", "..", "bin", "busybox") {
		t.Fatalf("expected absolute symlink to be rewritten under rootfs, got %q", target)
	}
}

func TestEnsureNoSymlinkParentsRejectsExtractionThroughSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := ensureNoSymlinkParents(root, filepath.Join(root, "escape", "payload")); err == nil {
		t.Fatal("expected extraction through symlink parent to be rejected")
	}
}

func TestCanCreateRuncCgroupPathRejectsTraversal(t *testing.T) {
	if err := canCreateRuncCgroupPath("../evil"); err == nil {
		t.Fatal("expected traversal cgroup path to be rejected")
	}
}

func TestCgroupPathForServiceUsesDelegatedParent(t *testing.T) {
	t.Setenv(cgroupParentEnv, "/docker/runtime-demo")

	path, err := cgroupPathForService("service.alpha")
	if err != nil {
		t.Fatalf("unexpected delegated cgroup path error: %v", err)
	}
	if path != "/docker/runtime-demo/mysterium-service.alpha" {
		t.Fatalf("unexpected delegated cgroup path %q", path)
	}
}

func TestCgroupPathForServiceRejectsRelativeParent(t *testing.T) {
	t.Setenv(cgroupParentEnv, "../outside")

	if _, err := cgroupPathForService("service.alpha"); err == nil {
		t.Fatal("expected relative delegated cgroup parent to be rejected")
	}
}

func TestMapContainerID(t *testing.T) {
	mappings := []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}

	hostID, ok := mapContainerID(mappings, 1000)
	if !ok || hostID != 101000 {
		t.Fatalf("unexpected mapped ID %d, mapped=%v", hostID, ok)
	}
	if _, ok := mapContainerID(mappings, 65536); ok {
		t.Fatal("expected ID outside the mapping to be rejected")
	}
	if _, ok := mapContainerID([]specs.LinuxIDMapping{{
		ContainerID: 0,
		HostID:      math.MaxUint32,
		Size:        2,
	}}, 1); ok {
		t.Fatal("expected overflowing host ID to be rejected")
	}
}
