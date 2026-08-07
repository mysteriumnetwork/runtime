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
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	runc "github.com/containerd/go-runc"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
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

func TestProcessFromImageRejectsRuntimeReservedEnvironment(t *testing.T) {
	for _, reserved := range []string{serviceBindAddressEnv, servicePortEnv} {
		t.Run(reserved, func(t *testing.T) {
			_, err := processFromImage(&v1.ConfigFile{Config: v1.Config{
				Entrypoint: []string{"/bin/server"},
				Env:        []string{reserved + "=caller-controlled"},
				User:       "1000:1000",
			}})
			if err == nil || !strings.Contains(err.Error(), "reserved by the runtime") {
				t.Fatalf("reserved environment variable was not rejected: %v", err)
			}
		})
	}
}

func TestRuntimeEnvironmentInjectionIsConsistent(t *testing.T) {
	options := testSpecOptions(IsolationProfile{
		Name:  BestEffortIsolationProfile,
		Level: RuntimeLevelLimited,
		Features: IsolationFeatures{
			MountNamespaces: true,
			NoNewPrivileges: true,
		},
	})
	options.ServiceBindAddress = "127.64.0.42"
	options.ServicePort = 4321
	options.Process.Env = []string{"IMAGE_VALUE=kept"}

	want := []string{
		"IMAGE_VALUE=kept",
		serviceBindAddressEnv + "=127.64.0.42",
		servicePortEnv + "=4321",
	}
	if got := processEnvironment(options); !equalStrings(got, want) {
		t.Fatalf("processEnvironment() = %#v, want %#v", got, want)
	}

	spec, err := buildOCISpec(options, nil, nil, "", 64*1024*1024)
	if err != nil {
		t.Fatalf("buildOCISpec() error = %v", err)
	}
	if !equalStrings(spec.Process.Env, want) {
		t.Fatalf("runc process environment = %#v, want %#v", spec.Process.Env, want)
	}

	direct := directLaunchConfigForOptions(options, "/runtime/rootfs")
	if !equalStrings(direct.Process.Env, want) {
		t.Fatalf("direct process environment = %#v, want %#v", direct.Process.Env, want)
	}
	if !equalStrings(options.Process.Env, []string{"IMAGE_VALUE=kept"}) {
		t.Fatalf("runtime injection mutated normalized image environment: %#v", options.Process.Env)
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

func TestValidateStoredOptionsAcceptsExplicitUnisolatedPolicy(t *testing.T) {
	options := testSpecOptions(IsolationProfile{
		Name:  UnisolatedProfile,
		Level: RuntimeLevelUnisolated,
		Features: IsolationFeatures{
			FilesystemJail:      true,
			NonRootUser:         true,
			CapabilitiesDropped: true,
			NoNewPrivileges:     true,
		},
	})
	options.OCIArtifact = "example.invalid/trusted@sha256:" + strings.Repeat("0", 64)
	options.MinimumRuntimeLevel = RuntimeLevelUnisolated

	if err := validateStoredOptions(options); err != nil {
		t.Fatalf("validateStoredOptions() error = %v", err)
	}
}

func TestAssignServiceBindAddressAllocationLifecycle(t *testing.T) {
	backend := &RuncBackend{services: make(map[string]Options)}
	hostProfile := IsolationProfile{Level: RuntimeLevelLimited}

	first := Options{Name: "first", ServicePort: 3000, Isolation: hostProfile}
	if err := backend.assignServiceBindAddressLocked(&first); err != nil {
		t.Fatal(err)
	}
	backend.services[first.Name] = first

	second := Options{Name: "second", ServicePort: 3000, Isolation: hostProfile}
	if err := backend.assignServiceBindAddressLocked(&second); err != nil {
		t.Fatal(err)
	}
	backend.services[second.Name] = second

	if first.ServiceBindAddress != "127.64.0.1" || second.ServiceBindAddress != "127.64.0.2" {
		t.Fatalf("unexpected allocations: first=%q second=%q", first.ServiceBindAddress, second.ServiceBindAddress)
	}
	if first.ServiceBindAddress == second.ServiceBindAddress || first.ServicePort != second.ServicePort {
		t.Fatal("services sharing one internal port did not receive distinct bind addresses")
	}

	update := Options{Name: first.Name, ServicePort: 4000, Isolation: hostProfile}
	if err := backend.assignServiceBindAddressLocked(&update); err != nil {
		t.Fatal(err)
	}
	if update.ServiceBindAddress != first.ServiceBindAddress {
		t.Fatalf("update changed allocation from %q to %q", first.ServiceBindAddress, update.ServiceBindAddress)
	}

	delete(backend.services, first.Name)
	replacement := Options{Name: "replacement", ServicePort: 3000, Isolation: hostProfile}
	if err := backend.assignServiceBindAddressLocked(&replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.ServiceBindAddress != first.ServiceBindAddress {
		t.Fatalf("released allocation was not reused: got %q want %q", replacement.ServiceBindAddress, first.ServiceBindAddress)
	}

	namespaced := Options{
		Name:      "namespaced",
		Isolation: IsolationProfile{Features: IsolationFeatures{NetworkNamespaces: true}},
	}
	if err := backend.assignServiceBindAddressLocked(&namespaced); err != nil {
		t.Fatal(err)
	}
	if namespaced.ServiceBindAddress != serviceLoopback {
		t.Fatalf("network-namespace allocation = %q, want %q", namespaced.ServiceBindAddress, serviceLoopback)
	}
}

func TestPersistedServiceBindAddressesReload(t *testing.T) {
	directory := t.TempDir()
	metadataPath := filepath.Join(directory, metadataFileName)
	backend := &RuncBackend{
		metadataPath: metadataPath,
		services: map[string]Options{
			"first":  testStoredOptions("first", "127.64.0.1", false),
			"second": testStoredOptions("second", "127.64.0.2", false),
		},
	}
	if err := backend.persistLocked(); err != nil {
		t.Fatalf("persistLocked() error = %v", err)
	}

	reloaded, err := (&RuncBackend{metadataPath: metadataPath}).loadServices()
	if err != nil {
		t.Fatalf("loadServices() error = %v", err)
	}
	for name, want := range backend.services {
		if got := reloaded[name].ServiceBindAddress; got != want.ServiceBindAddress {
			t.Errorf("reloaded %q address = %q, want %q", name, got, want.ServiceBindAddress)
		}
	}
}

func TestLoadServicesRejectsMalformedOrDuplicateBindAddresses(t *testing.T) {
	tests := map[string]map[string]Options{
		"outside pool": {
			"first": testStoredOptions("first", "127.0.0.1", false),
		},
		"malformed": {
			"first": testStoredOptions("first", "not-an-address", false),
		},
		"duplicate": {
			"first":  testStoredOptions("first", "127.64.0.9", false),
			"second": testStoredOptions("second", "127.64.0.9", false),
		},
		"namespace non-loopback": {
			"first": testStoredOptions("first", "127.64.0.9", true),
		},
	}
	for name, services := range tests {
		t.Run(name, func(t *testing.T) {
			metadataPath := filepath.Join(t.TempDir(), metadataFileName)
			data, err := json.Marshal(persistedServices{SchemaVersion: metadataSchemaVersion, Services: services})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(metadataPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (&RuncBackend{metadataPath: metadataPath}).loadServices(); err == nil {
				t.Fatal("invalid stored bind address metadata was accepted")
			}
		})
	}
}

func TestReadManifestRejectsCallerControlledBindAddress(t *testing.T) {
	rootfs := t.TempDir()
	manifest := `{
		"schema_version": 1,
		"service": {
			"protocol": "tcp",
			"internal_port": 3000,
			"service_bind_address": "127.64.0.99"
		},
		"resources": {}
	}`
	if err := os.WriteFile(filepath.Join(rootfs, manifestFileName), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(rootfs); err == nil {
		t.Fatal("manifest-provided service bind address was accepted")
	}
}

func TestParseJSONOptionsRejectsCallerControlledBindAddress(t *testing.T) {
	raw := json.RawMessage(`{
		"name": "service",
		"oci_artifact": "example.invalid/service@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"service_bind_address": "127.64.0.99"
	}`)
	if _, err := ParseJSONOptions(&raw); err == nil {
		t.Fatal("caller-provided service bind address was accepted")
	}
}

func TestDialRunningServiceSelectsNamespaceOrAssignedHostAddress(t *testing.T) {
	var hostAddress string
	var namespacePID, namespacePort int
	hostDial := func(_ string, address string, _ time.Duration) (net.Conn, error) {
		hostAddress = address
		return nil, nil
	}
	namespaceDial := func(pid, port int) (net.Conn, error) {
		namespacePID, namespacePort = pid, port
		return nil, nil
	}

	host := Options{ServiceBindAddress: "127.64.0.7"}
	if _, err := dialRunningService(host, 123, 3000, hostDial, namespaceDial); err != nil {
		t.Fatal(err)
	}
	if hostAddress != "127.64.0.7:3000" || namespacePID != 0 {
		t.Fatalf("host-network dial selected address=%q namespacePID=%d", hostAddress, namespacePID)
	}

	hostAddress = ""
	namespaced := Options{Isolation: IsolationProfile{Features: IsolationFeatures{NetworkNamespaces: true}}}
	if _, err := dialRunningService(namespaced, 456, 8080, hostDial, namespaceDial); err != nil {
		t.Fatal(err)
	}
	if hostAddress != "" || namespacePID != 456 || namespacePort != 8080 {
		t.Fatalf("namespace dial selected host=%q pid=%d port=%d", hostAddress, namespacePID, namespacePort)
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

// imageFromTarEntries builds a single-layer image whose layer tarball contains
// the given entries, mirroring how base image rootfs layers are packed.
func imageFromTarEntries(t *testing.T, entries []*tar.Header, contents map[string]string) v1.Image {
	t.Helper()

	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range entries {
		body := contents[header.Name]
		if header.Typeflag == tar.TypeReg {
			header.Size = int64(len(body))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("failed to write tar header %q: %v", header.Name, err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := io.WriteString(writer, body); err != nil {
				t.Fatalf("failed to write tar body %q: %v", header.Name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}

	payload := buffer.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	})
	if err != nil {
		t.Fatalf("failed to build layer: %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("failed to build image: %v", err)
	}
	return img
}

// currentUserMappings map container root onto the calling user so that the
// extractor's ownership mapping succeeds without privileges.
func currentUserMappings() ([]specs.LinuxIDMapping, []specs.LinuxIDMapping) {
	uid := []specs.LinuxIDMapping{{ContainerID: 0, HostID: uint32(os.Getuid()), Size: 1}}
	gid := []specs.LinuxIDMapping{{ContainerID: 0, HostID: uint32(os.Getgid()), Size: 1}}
	return uid, gid
}

func TestExtractImageRootFSHandlesRootEntryAndHardLinks(t *testing.T) {
	rootfs := t.TempDir()
	uidMappings, gidMappings := currentUserMappings()

	img := imageFromTarEntries(t, []*tar.Header{
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "usr/bin/perl", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "usr/bin/perl5.40.1", Typeflag: tar.TypeLink, Linkname: "usr/bin/perl", Mode: 0o755},
	}, map[string]string{"usr/bin/perl": "#!/bin/sh\n"})

	if err := extractImageRootFS(img, rootfs, maxRootFSSize, uidMappings, gidMappings); err != nil {
		t.Fatalf("expected extraction to succeed, got error: %v", err)
	}

	source, err := os.Stat(filepath.Join(rootfs, "usr/bin/perl"))
	if err != nil {
		t.Fatalf("expected hard link source to exist: %v", err)
	}
	link, err := os.Stat(filepath.Join(rootfs, "usr/bin/perl5.40.1"))
	if err != nil {
		t.Fatalf("expected hard link to exist: %v", err)
	}
	if !os.SameFile(source, link) {
		t.Fatal("expected hard link to share an inode with its source")
	}
}

func TestExtractImageRootFSRejectsUnsafeEntries(t *testing.T) {
	uidMappings, gidMappings := currentUserMappings()

	tests := map[string][]*tar.Header{
		// Relative link targets that escape the rootfs are dropped by
		// mutate.Extract before they reach the extractor, so they cannot be
		// exercised here; secureJoinUnder covers that guard directly. Absolute
		// targets are passed through unchanged and must be rejected by us.
		"hard link to absolute host path": {
			{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "usr/passwd", Typeflag: tar.TypeLink, Linkname: "/etc/passwd", Mode: 0o644},
		},
		"hard link to missing source": {
			{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "usr/perl", Typeflag: tar.TypeLink, Linkname: "usr/bin/perl", Mode: 0o755},
		},
		"root entry that is not a directory": {
			{Name: ".", Typeflag: tar.TypeReg, Mode: 0o644},
		},
		"device node": {
			{Name: "dev/", Typeflag: tar.TypeDir, Mode: 0o755},
			{Name: "dev/null", Typeflag: tar.TypeChar, Mode: 0o666},
		},
	}

	for description, entries := range tests {
		t.Run(description, func(t *testing.T) {
			img := imageFromTarEntries(t, entries, nil)
			err := extractImageRootFS(img, t.TempDir(), maxRootFSSize, uidMappings, gidMappings)
			if err == nil {
				t.Fatalf("expected %s to be rejected", description)
			}
		})
	}
}

func TestIsRootTarEntry(t *testing.T) {
	roots := []string{".", "./", "/", "", "./."}
	for _, name := range roots {
		if !isRootTarEntry(name) {
			t.Fatalf("expected entry %q to be the rootfs directory", name)
		}
	}

	nonRoots := []string{"bin", "./bin", "/etc/passwd", "..", "\x00"}
	for _, name := range nonRoots {
		if isRootTarEntry(name) {
			t.Fatalf("expected entry %q not to be the rootfs directory", name)
		}
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

func TestRuncForProfileUsesRootlessCgroupManagerWithoutCgroups(t *testing.T) {
	base := &runc.Runc{}
	backend := &RuncBackend{runc: base}

	runner := backend.runcForProfile(IsolationProfile{})
	if runner == base {
		t.Fatal("cgroup-less profile mutated the shared runc client")
	}
	if runner.Rootless == nil || !*runner.Rootless {
		t.Fatal("cgroup-less profile did not enable runc's rootless cgroup manager")
	}
	if base.Rootless != nil {
		t.Fatal("cgroup-less profile changed the shared runc client")
	}
}

func TestRuncForProfilePreservesCgroupManagerWithCgroups(t *testing.T) {
	base := &runc.Runc{}
	backend := &RuncBackend{runc: base}
	profile := IsolationProfile{Features: IsolationFeatures{Cgroups: true}}

	if runner := backend.runcForProfile(profile); runner != base {
		t.Fatal("cgroup-enabled profile did not preserve the shared runc client")
	}
}

func TestRuncCreateOptionsUseSeccompLimitedCompatibilityFallbacks(t *testing.T) {
	profile := IsolationProfile{
		Level:    RuntimeLevelLimited,
		Features: IsolationFeatures{Seccomp: true},
	}

	if opts := runcCreateOptions(profile, nil); !opts.NoNewKeyring || !opts.NoPivot {
		t.Fatalf("seccomp-enabled limited profile did not enable runc compatibility fallbacks: %#v", opts)
	}
}

func TestRuncCreateOptionsKeepFullRuncIsolationDefaults(t *testing.T) {
	profiles := []IsolationProfile{
		{Level: RuntimeLevelLimited},
		{Level: RuntimeLevelFull, Features: IsolationFeatures{Seccomp: true}},
	}
	for _, profile := range profiles {
		if opts := runcCreateOptions(profile, nil); opts.NoNewKeyring || opts.NoPivot {
			t.Fatalf("profile level %q with seccomp=%t unexpectedly weakened runc isolation defaults",
				profile.Level, profile.Features.Seccomp)
		}
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

func TestBuildOCISpecUsesLimitedIsolationProfile(t *testing.T) {
	options := testSpecOptions(IsolationProfile{
		Name:  BestEffortIsolationProfile,
		Level: RuntimeLevelLimited,
		Features: IsolationFeatures{
			MountNamespaces: true,
			NoNewPrivileges: true,
		},
	})

	spec, err := buildOCISpec(options, nil, nil, "", 64*1024*1024)
	if err != nil {
		t.Fatalf("buildOCISpec() error = %v", err)
	}
	if spec.Root.Readonly {
		t.Fatal("limited profile unexpectedly made the rootfs read-only")
	}
	if spec.Linux.Seccomp != nil || spec.Linux.Resources != nil || spec.Linux.CgroupsPath != "" {
		t.Fatalf("limited profile enabled unavailable controls: %#v", spec.Linux)
	}
	if len(spec.Linux.UIDMappings) != 0 || len(spec.Linux.GIDMappings) != 0 {
		t.Fatal("limited profile unexpectedly configured user namespace mappings")
	}
	if hasNamespace(spec.Linux.Namespaces, specs.UserNamespace) ||
		hasNamespace(spec.Linux.Namespaces, specs.PIDNamespace) ||
		hasNamespace(spec.Linux.Namespaces, specs.NetworkNamespace) ||
		hasNamespace(spec.Linux.Namespaces, specs.IPCNamespace) {
		t.Fatalf("limited profile enabled unavailable namespaces: %#v", spec.Linux.Namespaces)
	}
	if !hasNamespace(spec.Linux.Namespaces, specs.MountNamespace) {
		t.Fatal("limited profile is missing its required mount namespace")
	}
}

func TestValidateUnisolatedProfile(t *testing.T) {
	profile := IsolationProfile{
		Name:  UnisolatedProfile,
		Level: RuntimeLevelUnisolated,
		Features: IsolationFeatures{
			FilesystemJail:      true,
			NonRootUser:         true,
			CapabilitiesDropped: true,
			NoNewPrivileges:     true,
		},
	}
	if err := validateIsolationProfile(profile); err != nil {
		t.Fatalf("validateIsolationProfile() error = %v", err)
	}

	profile.Features.NetworkNamespaces = true
	if err := validateIsolationProfile(profile); err == nil {
		t.Fatal("unisolated profile claimed a namespace without being rejected")
	}
}

func TestDirectProcessIdentityMatchesCurrentProcess(t *testing.T) {
	state, ok := directProcessIdentity(os.Getpid())
	if !ok {
		t.Fatal("current process identity was not detected")
	}
	if !directProcessMatches(state) {
		t.Fatal("current process identity did not match itself")
	}
	state.StartTime++
	if directProcessMatches(state) {
		t.Fatal("mismatched process start time was accepted")
	}
}

func TestDirectExecutorLaunchesAndStopsWithoutRunc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("direct executor integration test requires root")
	}
	for _, capability := range []uint{5, 6, 7, 18} {
		if !hasEffectiveCapability(capability) {
			t.Skipf("%s is unavailable", effectiveCapabilityName(capability))
		}
	}
	executable := ""
	for _, candidate := range []string{"/usr/bin/sleep", "/bin/sleep"} {
		if _, err := os.Stat(candidate); err == nil {
			executable = candidate
			break
		}
	}
	if executable == "" {
		t.Skip("sleep executable is unavailable")
	}

	configPath := filepath.Join(t.TempDir(), "direct-launch.json")
	config := directLaunchConfig{
		RootFS: "/",
		Process: ProcessDefinition{
			Args: []string{executable, "30"},
			Env:  []string{"PATH=/usr/bin:/bin"},
			Cwd:  "/",
			UID:  65534,
			GID:  65534,
		},
		NoNewPrivileges: true,
	}
	if err := writeSecureJSON(configPath, config); err != nil {
		t.Fatalf("writeSecureJSON() error = %v", err)
	}
	process, err := startDirectProcess(configPath)
	if err != nil {
		t.Fatalf("startDirectProcess() error = %v", err)
	}
	state, ok := directProcessIdentity(process.Pid)
	if !ok || !directProcessMatches(state) {
		_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
		_, _ = process.Wait()
		t.Fatal("direct workload did not expose a stable process identity")
	}
	if err := syscall.Kill(-process.Pid, syscall.SIGTERM); err != nil {
		_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
		_, _ = process.Wait()
		t.Fatalf("terminate direct workload: %v", err)
	}
	if _, err := process.Wait(); err != nil {
		t.Fatalf("wait for direct workload: %v", err)
	}
	if directProcessMatches(state) {
		t.Fatal("direct workload remained active after termination")
	}
}

func TestBuildOCISpecUsesFullIsolationProfile(t *testing.T) {
	options := testSpecOptions(IsolationProfile{
		Name:  FullIsolationProfile,
		Level: RuntimeLevelFull,
		Features: IsolationFeatures{
			UserNamespaces:    true,
			MountNamespaces:   true,
			PIDNamespaces:     true,
			NetworkNamespaces: true,
			IPCNamespaces:     true,
			Cgroups:           true,
			Seccomp:           true,
			NoNewPrivileges:   true,
			ReadOnlyRootFS:    true,
		},
	})
	mappings := []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}

	spec, err := buildOCISpec(
		options,
		mappings,
		mappings,
		"/runtime/mysterium-test",
		64*1024*1024,
	)
	if err != nil {
		t.Fatalf("buildOCISpec() error = %v", err)
	}
	if !spec.Root.Readonly || spec.Linux.Seccomp == nil || spec.Linux.Resources == nil {
		t.Fatalf("full profile is missing isolation controls: %#v", spec.Linux)
	}
	if spec.Linux.CgroupsPath != "/runtime/mysterium-test" {
		t.Fatalf("unexpected cgroup path %q", spec.Linux.CgroupsPath)
	}
	for _, namespace := range []specs.LinuxNamespaceType{
		specs.UserNamespace,
		specs.MountNamespace,
		specs.PIDNamespace,
		specs.NetworkNamespace,
		specs.IPCNamespace,
	} {
		if !hasNamespace(spec.Linux.Namespaces, namespace) {
			t.Errorf("full profile is missing namespace %q", namespace)
		}
	}
}

func testSpecOptions(profile IsolationProfile) Options {
	bindAddress := "127.64.0.1"
	if profile.Features.NetworkNamespaces {
		bindAddress = serviceLoopback
	}
	return Options{
		Name:               "runtime.test",
		ServicePort:        3000,
		ServiceBindAddress: bindAddress,
		Process: ProcessDefinition{
			Args: []string{"/bin/server"},
			Cwd:  "/",
			UID:  1000,
			GID:  1000,
		},
		ResourceLimits: ResourceLimits{
			CPU:    "1",
			Memory: "512MiB",
			Disk:   "64MiB",
			Pids:   128,
		},
		Isolation: profile,
	}
}

func testStoredOptions(name, bindAddress string, networkNamespace bool) Options {
	profile := IsolationProfile{
		Name:  UnisolatedProfile,
		Level: RuntimeLevelUnisolated,
		Features: IsolationFeatures{
			FilesystemJail:      true,
			NonRootUser:         true,
			CapabilitiesDropped: true,
			NoNewPrivileges:     true,
		},
	}
	minimum := RuntimeLevelUnisolated
	if networkNamespace {
		profile = IsolationProfile{
			Name:  FullIsolationProfile,
			Level: RuntimeLevelFull,
			Features: IsolationFeatures{
				FilesystemJail:      true,
				NonRootUser:         true,
				CapabilitiesDropped: true,
				UserNamespaces:      true,
				MountNamespaces:     true,
				PIDNamespaces:       true,
				NetworkNamespaces:   true,
				IPCNamespaces:       true,
				Cgroups:             true,
				Seccomp:             true,
				NoNewPrivileges:     true,
				ReadOnlyRootFS:      true,
			},
		}
		minimum = RuntimeLevelFull
	}
	options := testSpecOptions(profile)
	options.Name = name
	options.OCIArtifact = "example.invalid/" + name + "@sha256:" + strings.Repeat("0", 64)
	options.ServiceBindAddress = bindAddress
	options.MinimumRuntimeLevel = minimum
	return options
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasNamespace(namespaces []specs.LinuxNamespace, expected specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if namespace.Type == expected {
			return true
		}
	}
	return false
}
