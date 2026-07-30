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
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	runc "github.com/containerd/go-runc"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

const (
	runtimeBackendDirName = "runtime-services"
	metadataFileName      = "services.json"
	bundlesDirName        = "bundles"
	runcRootDirName       = "runc-root"
	runcLogFileName       = "runc.log"
	configFileName        = "config.json"
	rootfsDirName         = "rootfs"
	manifestFileName      = "mysterium-runtime.json"
	cgroupParentEnv       = "MYSTERIUM_CGROUP_PARENT"
	defaultCPUPeriod      = uint64(100000)
	stopTimeout           = 5 * time.Second
	runcOperationTimeout  = 30 * time.Second
	imagePullTimeout      = 5 * time.Minute
	maxServiceNameLength  = 128
	maxManifestSize       = 64 * 1024
	maxRootFSSize         = uint64(1024 * 1024 * 1024)
	maxInstalledServices  = 4
	metadataSchemaVersion = 3
)

var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type persistedServices struct {
	SchemaVersion int                `json:"schema_version"`
	Services      map[string]Options `json:"services"`
}

// RuncBackend manages OCI-isolated services via runc and explicitly trusted
// unisolated services via the built-in direct executor. The name is retained
// to preserve the existing concrete API.
type RuncBackend struct {
	mu           sync.Mutex
	baseDir      string
	bundlesDir   string
	metadataPath string
	runc         *runc.Runc
	services     map[string]Options
	initErr      error
	status       RuntimeStatus
	hostChecks   runtimeHostChecks

	caps         capabilities.RuntimeCapabilities
	detailedCaps capabilities.DetailedCapabilities
}

// NewBackend creates the default runtime backend implementation.
func NewBackend(runtimeDir string) Backend {
	return newRuncBackend(runtimeDir)
}

func newRuncBackend(runtimeDir string) *RuncBackend {
	baseDir := filepath.Join(runtimeDir, runtimeBackendDirName)
	caps, detailedCaps := capabilities.Detect()
	backend := &RuncBackend{
		baseDir:      baseDir,
		bundlesDir:   filepath.Join(baseDir, bundlesDirName),
		metadataPath: filepath.Join(baseDir, metadataFileName),
		runc: &runc.Runc{
			Command:   runc.DefaultCommand,
			Root:      filepath.Join(baseDir, runcRootDirName),
			Debug:     true,
			Log:       filepath.Join(baseDir, runcLogFileName),
			LogFormat: runc.JSON,
		},
		services:     make(map[string]Options),
		caps:         caps,
		detailedCaps: detailedCaps,
	}

	backend.initErr = backend.initialize()
	backend.hostChecks = inspectRuntimeHost()
	if backend.initErr == nil {
		backend.hostChecks.directExecutorAvailable, backend.hostChecks.directExecutorReason =
			probeDirectExecutor(backend.baseDir, backend.caps.NoNewPrivileges)
	}
	backend.status = assessRuntime(backend.caps, backend.initErr, backend.hostChecks)
	return backend
}

func (backend *RuncBackend) initialize() error {
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{
		{path: backend.baseDir, mode: 0o711},
		{path: backend.bundlesDir, mode: 0o711},
		{path: backend.runc.Root, mode: 0o700},
	} {
		if err := os.MkdirAll(dir.path, dir.mode); err != nil {
			return errors.Wrapf(err, "failed to create runtime backend directory %q", dir.path)
		}
		if err := os.Chmod(dir.path, dir.mode); err != nil {
			return errors.Wrapf(err, "failed to secure runtime backend directory %q", dir.path)
		}
	}

	if evalDir, err := filepath.EvalSymlinks(backend.baseDir); err == nil && evalDir != "" {
		backend.baseDir = evalDir
		backend.bundlesDir = filepath.Join(evalDir, bundlesDirName)
		backend.metadataPath = filepath.Join(evalDir, metadataFileName)
		backend.runc.Root = filepath.Join(evalDir, runcRootDirName)
		backend.runc.Log = filepath.Join(evalDir, runcLogFileName)
	}

	services, err := backend.loadServices()
	if err != nil {
		return err
	}
	backend.services = services
	return nil
}

func (backend *RuncBackend) Create(input CreateOptions) error {
	minimumLevel, err := normalizeMinimumRuntimeLevel(input.MinimumRuntimeLevel)
	if err != nil {
		return err
	}
	input.MinimumRuntimeLevel = minimumLevel
	if err := backend.ensureSpawnReady(minimumLevel); err != nil {
		return err
	}
	if err := validateServiceName(input.Name); err != nil {
		return err
	}
	if input.OCIArtifact == "" {
		return errors.New("oci_artifact is required")
	}
	if _, err := name.NewDigest(input.OCIArtifact, name.StrictValidation); err != nil {
		return errors.Wrap(err, "oci_artifact must be an immutable digest reference")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	active, err := backend.activeLocked()
	if err != nil {
		return err
	}
	if _, active := active[input.Name]; active {
		return errors.Errorf("runtime service %q is active", input.Name)
	}
	if _, updating := backend.services[input.Name]; !updating && len(backend.services) >= maxInstalledServices {
		return errors.Errorf("at most %d runtime services may be installed", maxInstalledServices)
	}

	bundleDir := backend.bundleDir(input.Name)
	stagingDir, err := os.MkdirTemp(backend.bundlesDir, "."+input.Name+"-staging-")
	if err != nil {
		return errors.Wrapf(err, "failed to stage bundle for %q", input.Name)
	}
	defer os.RemoveAll(stagingDir)
	if err := os.Chmod(stagingDir, 0o711); err != nil {
		return errors.Wrapf(err, "failed to make staged bundle traversable for %q", input.Name)
	}
	if err := os.MkdirAll(filepath.Join(stagingDir, rootfsDirName), 0o755); err != nil {
		return errors.Wrapf(err, "failed to create bundle rootfs for %q", input.Name)
	}

	preparedOptions, err := backend.prepareBundleLocked(input, stagingDir)
	if err != nil {
		return err
	}

	if preparedOptions.Isolation.Level != RuntimeLevelUnisolated {
		if err := backend.writeSpec(stagingDir, preparedOptions); err != nil {
			return err
		}
	}

	backupDir := filepath.Join(backend.bundlesDir, "."+input.Name+"-previous")
	if err := os.RemoveAll(backupDir); err != nil {
		return errors.Wrapf(err, "failed to clear previous bundle backup for %q", input.Name)
	}
	hadBundle := false
	if _, err := os.Lstat(bundleDir); err == nil {
		hadBundle = true
		if err := os.Rename(bundleDir, backupDir); err != nil {
			return errors.Wrapf(err, "failed to preserve existing bundle for %q", input.Name)
		}
	} else if !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to inspect existing bundle for %q", input.Name)
	}
	if err := os.Rename(stagingDir, bundleDir); err != nil {
		if hadBundle {
			_ = os.Rename(backupDir, bundleDir)
		}
		return errors.Wrapf(err, "failed to install validated bundle for %q", input.Name)
	}

	oldOptions, hadOptions := backend.services[input.Name]
	backend.services[preparedOptions.Name] = preparedOptions
	if err := backend.persistLocked(); err != nil {
		_ = os.RemoveAll(bundleDir)
		if hadBundle {
			_ = os.Rename(backupDir, bundleDir)
		}
		if hadOptions {
			backend.services[input.Name] = oldOptions
		} else {
			delete(backend.services, input.Name)
		}
		return err
	}
	_ = os.RemoveAll(backupDir)
	return nil
}

func (backend *RuncBackend) Delete(name string) error {
	if err := backend.ensureInitialized(); err != nil {
		return err
	}
	if err := validateServiceName(name); err != nil {
		return err
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	options, exists := backend.services[name]
	if exists {
		if err := backend.stopContainerLocked(options); err != nil {
			return err
		}
	}

	delete(backend.services, name)
	if err := backend.persistLocked(); err != nil {
		return err
	}

	if err := os.RemoveAll(backend.bundleDir(name)); err != nil {
		return errors.Wrapf(err, "failed to delete bundle for %q", name)
	}
	return nil
}

func (backend *RuncBackend) Start(name string) error {
	if err := backend.ensureInitialized(); err != nil {
		return err
	}
	if err := validateServiceName(name); err != nil {
		return err
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	options, exists := backend.services[name]
	if !exists {
		return errors.Errorf("runtime service %q is not created", name)
	}
	if err := backend.ensureSpawnReady(options.MinimumRuntimeLevel); err != nil {
		return errors.Wrapf(err, "runtime service %q cannot meet its minimum runtime level", name)
	}
	if err := backend.ensureProfileSupported(options.Isolation); err != nil {
		return errors.Wrapf(err, "runtime service %q isolation profile is unavailable", name)
	}

	bundleDir := backend.bundleDir(name)
	if !isPathWithinRoot(backend.bundlesDir, bundleDir) {
		return errors.Errorf("runtime bundle for %q escapes managed directory", name)
	}
	if options.Isolation.Level == RuntimeLevelUnisolated {
		if _, err := os.Stat(filepath.Join(bundleDir, rootfsDirName)); err != nil {
			return errors.Wrapf(err, "runtime service %q has no validated rootfs", name)
		}
		return backend.startDirectLocked(options)
	}
	if _, err := os.Stat(filepath.Join(bundleDir, configFileName)); err != nil {
		return errors.Wrapf(err, "runtime service %q has no validated OCI bundle", name)
	}

	return backend.startRuncLocked(options, bundleDir)
}

func (backend *RuncBackend) startRuncLocked(options Options, bundleDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), runcOperationTimeout)
	defer cancel()
	state, err := backend.runc.State(ctx, backend.containerID(options.Name))
	if err == nil && state != nil && state.Status != "stopped" {
		return nil
	}

	_ = backend.runc.Delete(ctx, backend.containerID(options.Name), &runc.DeleteOpts{Force: true})

	stdio, err := runc.NewNullIO()
	if err != nil {
		return errors.Wrap(err, "failed to create null io")
	}

	if err := backend.runc.Create(ctx, backend.containerID(options.Name), bundleDir, &runc.CreateOpts{
		IO: stdio,
	}); err != nil {
		return backend.wrapRuncError("create", options.Name, err)
	}

	if options.Isolation.Features.NetworkNamespaces {
		state, stateErr := backend.runc.State(ctx, backend.containerID(options.Name))
		if stateErr != nil || state == nil || state.Pid <= 0 {
			_ = backend.forceDelete(options.Name)
			if stateErr != nil {
				return errors.Wrapf(stateErr, "failed to inspect created runtime service %q", options.Name)
			}
			return errors.Errorf("created runtime service %q has no process", options.Name)
		}
		if err := configureLoopback(state.Pid); err != nil {
			_ = backend.forceDelete(options.Name)
			return errors.Wrapf(err, "failed to configure network namespace for %q", options.Name)
		}
	}

	if err := backend.runc.Start(ctx, backend.containerID(options.Name)); err != nil {
		_ = backend.forceDelete(options.Name)
		return backend.wrapRuncError("start", options.Name, err)
	}

	if state, err := backend.runc.State(ctx, backend.containerID(options.Name)); err != nil || state == nil || state.Pid <= 0 {
		_ = backend.stopContainerLocked(options)
		return errors.Errorf("started runtime service %q has no process", options.Name)
	}

	return nil
}

func (backend *RuncBackend) Stop(name string) error {
	if err := backend.ensureInitialized(); err != nil {
		return err
	}
	if err := validateServiceName(name); err != nil {
		return err
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	options, exists := backend.services[name]
	if !exists {
		return nil
	}
	return backend.stopContainerLocked(options)
}

// DialTCP connects to a TCP listener on loopback inside a running workload.
func (backend *RuncBackend) DialTCP(name string, port int) (net.Conn, error) {
	if err := backend.ensureInitialized(); err != nil {
		return nil, err
	}
	if err := validateServiceName(name); err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("runtime service TCP port must be between 1 and 65535")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	options, exists := backend.services[name]
	if !exists {
		return nil, errors.Errorf("runtime service %q is not created", name)
	}
	if options.Isolation.Level == RuntimeLevelUnisolated {
		state, err := backend.directStateLocked(name)
		if err != nil {
			return nil, err
		}
		if state == nil {
			return nil, errors.Errorf("runtime service %q is not running", name)
		}
		return net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), runcOperationTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), runcOperationTimeout)
	defer cancel()
	state, err := backend.runc.State(ctx, backend.containerID(name))
	if err != nil {
		return nil, backend.wrapRuncError("inspect", name, err)
	}
	if state == nil || state.Pid <= 0 || state.Status != "running" {
		return nil, errors.Errorf("runtime service %q is not running", name)
	}

	if options.Isolation.Features.NetworkNamespaces {
		return dialTCPInNamespace(state.Pid, port)
	}
	return net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), runcOperationTimeout)
}

func (backend *RuncBackend) List() ([]ServiceInfo, error) {
	if err := backend.ensureInitialized(); err != nil {
		return nil, err
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	active, err := backend.activeLocked()
	if err != nil {
		return nil, err
	}
	result := make([]ServiceInfo, 0, len(backend.services))
	for name, options := range backend.services {
		state := ServiceStatePassive
		if _, ok := active[name]; ok {
			state = ServiceStateActive
		}
		result = append(result, ServiceInfo{Name: name, State: state, Options: options})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

func (backend *RuncBackend) Capabilities() (capabilities.RuntimeCapabilities, capabilities.DetailedCapabilities) {
	return backend.caps, backend.detailedCaps
}

func (backend *RuncBackend) Status() RuntimeStatus {
	return cloneRuntimeStatus(backend.status)
}

func (backend *RuncBackend) Availability() (bool, string) {
	if backend.status.Level == RuntimeLevelUnavailable {
		return false, strings.Join(backend.status.BlockingReasons, ", ")
	}
	if backend.status.Level == RuntimeLevelUnisolated {
		return true, "unisolated trusted execution only: " + strings.Join(backend.status.MissingForLimited, ", ")
	}
	if backend.status.Level == RuntimeLevelLimited {
		return true, "limited isolation: " + strings.Join(backend.status.MissingForFull, ", ")
	}
	return true, ""
}

func (backend *RuncBackend) ensureInitialized() error {
	if backend.initErr != nil {
		return backend.initErr
	}
	return nil
}

func (backend *RuncBackend) ensureSpawnReady(minimum RuntimeLevel) error {
	if err := backend.ensureInitialized(); err != nil {
		return err
	}
	normalized, err := normalizeMinimumRuntimeLevel(minimum)
	if err != nil {
		return err
	}
	if backend.status.Level == RuntimeLevelUnavailable {
		return errors.Errorf(
			"runtime service unavailable: %s",
			strings.Join(backend.status.BlockingReasons, ", "),
		)
	}
	if runtimeLevelRank(backend.status.Level) < runtimeLevelRank(normalized) {
		reasons := backend.status.MissingForLimited
		if normalized == RuntimeLevelFull {
			reasons = uniqueSorted(append(
				append([]string(nil), backend.status.MissingForLimited...),
				backend.status.MissingForFull...,
			))
		}
		return errors.Errorf(
			"runtime level %q does not satisfy required minimum %q: %s",
			backend.status.Level,
			normalized,
			strings.Join(reasons, ", "),
		)
	}
	return nil
}

func (backend *RuncBackend) ensureProfileSupported(profile IsolationProfile) error {
	if err := validateIsolationProfile(profile); err != nil {
		return err
	}
	if profile.Level == RuntimeLevelUnisolated && !backend.hostChecks.directExecutorAvailable {
		reason := backend.hostChecks.directExecutorReason
		if reason == "" {
			reason = "built-in direct executor is unavailable"
		}
		return errors.New(reason)
	}
	if runtimeLevelRank(backend.status.Level) < runtimeLevelRank(profile.Level) {
		return errors.Errorf("runtime level %q is below stored profile level %q", backend.status.Level, profile.Level)
	}
	available := backend.status.Profile.Features
	required := profile.Features
	var missing []string
	for _, feature := range []struct {
		name      string
		required  bool
		available bool
	}{
		{"filesystem jail", required.FilesystemJail, available.FilesystemJail},
		{"non-root user", required.NonRootUser, available.NonRootUser},
		{"capability dropping", required.CapabilitiesDropped, available.CapabilitiesDropped},
		{"user namespaces", required.UserNamespaces, available.UserNamespaces},
		{"mount namespaces", required.MountNamespaces, available.MountNamespaces},
		{"PID namespaces", required.PIDNamespaces, available.PIDNamespaces},
		{"network namespaces", required.NetworkNamespaces, available.NetworkNamespaces},
		{"IPC namespaces", required.IPCNamespaces, available.IPCNamespaces},
		{"cgroup resource isolation", required.Cgroups, available.Cgroups},
		{"seccomp", required.Seccomp, available.Seccomp},
		{"no_new_privileges", required.NoNewPrivileges, available.NoNewPrivileges},
		{"read-only rootfs", required.ReadOnlyRootFS, available.ReadOnlyRootFS},
	} {
		if feature.required && !feature.available {
			missing = append(missing, feature.name)
		}
	}
	if len(missing) > 0 {
		return errors.Errorf("required features are unavailable: %s", strings.Join(missing, ", "))
	}
	if profile.Level != RuntimeLevelUnisolated && !required.UserNamespaces {
		var missingCapabilities []string
		for _, bit := range []uint{21, 27} {
			if !backend.hostChecks.effectiveCapabilities[bit] {
				missingCapabilities = append(missingCapabilities, effectiveCapabilityName(bit))
			}
		}
		if len(missingCapabilities) > 0 {
			return errors.Errorf(
				"rootful profile requires unavailable capabilities: %s",
				strings.Join(missingCapabilities, ", "),
			)
		}
	}
	return nil
}

func (backend *RuncBackend) stopContainerLocked(options Options) error {
	if options.Isolation.Level == RuntimeLevelUnisolated {
		return backend.stopDirectLocked(options.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout+5*time.Second)
	defer cancel()
	id := backend.containerID(options.Name)

	state, err := backend.runc.State(ctx, id)
	if err == nil && state != nil && state.Status != "stopped" {
		_ = backend.runc.Kill(ctx, id, int(syscall.SIGTERM), &runc.KillOpts{All: true})
		deadline := time.Now().Add(stopTimeout)
		for time.Now().Before(deadline) {
			state, err = backend.runc.State(ctx, id)
			if err != nil || state == nil || state.Status == "stopped" {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	if err := backend.forceDelete(options.Name); err != nil && !isContainerMissingError(err) {
		return errors.Wrapf(err, "failed to delete runc container %q", options.Name)
	}

	return nil
}

func (backend *RuncBackend) forceDelete(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return backend.runc.Delete(ctx, backend.containerID(name), &runc.DeleteOpts{Force: true})
}

func (backend *RuncBackend) activeLocked() (map[string]struct{}, error) {
	active := make(map[string]struct{})
	if backend.hostChecks.runcAvailable {
		ctx, cancel := context.WithTimeout(context.Background(), runcOperationTimeout)
		defer cancel()
		containers, err := backend.runc.List(ctx)
		if err != nil {
			return nil, backend.wrapRuncError("list", "", err)
		}
		for _, container := range containers {
			if container == nil {
				continue
			}
			if container.Status == "running" || container.Status == "created" || container.Status == "paused" {
				active[container.ID] = struct{}{}
			}
		}
	}
	for name, options := range backend.services {
		if options.Isolation.Level != RuntimeLevelUnisolated {
			continue
		}
		state, err := backend.directStateLocked(name)
		if err != nil {
			return nil, err
		}
		if state != nil {
			active[name] = struct{}{}
		}
	}
	return active, nil
}

func (backend *RuncBackend) prepareBundleLocked(input CreateOptions, bundleDir string) (Options, error) {
	ref, err := name.NewDigest(input.OCIArtifact, name.StrictValidation)
	if err != nil {
		return Options{}, errors.Wrap(err, "failed to parse immutable OCI artifact reference")
	}

	ctx, cancel := context.WithTimeout(context.Background(), imagePullTimeout)
	defer cancel()
	img, err := remote.Image(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}),
	)
	if err != nil {
		return Options{}, errors.Wrap(err, "failed to pull OCI artifact")
	}

	configFile, err := img.ConfigFile()
	if err != nil {
		return Options{}, errors.Wrap(err, "failed to read OCI image config")
	}
	process, err := processFromImage(configFile)
	if err != nil {
		return Options{}, err
	}
	profile := backend.status.Profile
	uidMappings, gidMappings, err := rootFSOwnershipMappings(profile)
	if err != nil {
		return Options{}, err
	}

	rootfsPath := filepath.Join(bundleDir, rootfsDirName)
	if err := extractImageRootFS(img, rootfsPath, maxRootFSSize, uidMappings, gidMappings); err != nil {
		return Options{}, err
	}
	manifest, err := readManifest(rootfsPath)
	if err != nil {
		return Options{}, err
	}
	limits, err := validateManifest(manifest)
	if err != nil {
		return Options{}, err
	}

	return Options{
		Name:                input.Name,
		OCIArtifact:         input.OCIArtifact,
		ServicePort:         manifest.Service.InternalPort,
		Process:             process,
		ResourceLimits:      limits,
		Isolation:           profile,
		MinimumRuntimeLevel: input.MinimumRuntimeLevel,
	}, nil
}

func (backend *RuncBackend) writeSpec(bundleDir string, options Options) error {
	if len(options.Process.Args) == 0 {
		return errors.New("OCI image must define Entrypoint or Cmd")
	}
	uidMappings, gidMappings, err := rootFSOwnershipMappings(options.Isolation)
	if err != nil {
		return err
	}
	if !mappingContains(uidMappings, options.Process.UID) || !mappingContains(gidMappings, options.Process.GID) {
		return errors.New("OCI image user is outside the configured subordinate ID mapping")
	}
	diskBytes, ok := parseBytes(options.ResourceLimits.Disk)
	if !ok || diskBytes == 0 {
		return errors.New("manifest disk resource limit is invalid")
	}
	cgroupPath := ""
	if options.Isolation.Features.Cgroups {
		cgroupPath, err = cgroupPathForService(options.Name)
		if err != nil {
			return err
		}
	}
	spec, err := buildOCISpec(options, uidMappings, gidMappings, cgroupPath, diskBytes)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to encode OCI spec")
	}
	if err := os.WriteFile(filepath.Join(bundleDir, configFileName), data, 0o600); err != nil {
		return errors.Wrap(err, "failed to write OCI config.json")
	}
	return nil
}

func buildOCISpec(
	options Options,
	uidMappings []specs.LinuxIDMapping,
	gidMappings []specs.LinuxIDMapping,
	cgroupPath string,
	diskBytes uint64,
) (specs.Spec, error) {
	features := options.Isolation.Features
	if !features.MountNamespaces || !features.NoNewPrivileges {
		return specs.Spec{}, errors.New("isolation profile does not meet the minimum execution requirements")
	}

	namespaces := []specs.LinuxNamespace{
		{Type: specs.MountNamespace},
		{Type: specs.UTSNamespace},
	}
	if features.PIDNamespaces {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.PIDNamespace})
	}
	if features.NetworkNamespaces {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}
	if features.IPCNamespaces {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.IPCNamespace})
	}
	if features.UserNamespaces {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
	}

	linux := &specs.Linux{
		Namespaces: namespaces,
		MaskedPaths: []string{
			"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
			"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
			"/proc/sched_debug", "/sys/firmware",
		},
		ReadonlyPaths: []string{
			"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
		},
	}
	if features.UserNamespaces {
		linux.UIDMappings = append([]specs.LinuxIDMapping(nil), uidMappings...)
		linux.GIDMappings = append([]specs.LinuxIDMapping(nil), gidMappings...)
	}
	if features.Cgroups {
		if cgroupPath == "" {
			return specs.Spec{}, errors.New("cgroup isolation requested without a cgroup path")
		}
		linux.CgroupsPath = cgroupPath
		linux.Resources = buildLinuxResources(options.ResourceLimits)
	}
	if features.Seccomp {
		errno := uint(unix.EPERM)
		linux.Seccomp = &specs.LinuxSeccomp{
			DefaultAction: specs.ActAllow,
			Syscalls: []specs.LinuxSyscall{{
				Names: []string{
					"acct", "add_key", "bpf", "clock_adjtime", "create_module",
					"delete_module", "finit_module", "init_module", "ioperm",
					"iopl", "keyctl", "kexec_file_load", "kexec_load",
					"lookup_dcookie", "mount", "move_mount", "name_to_handle_at",
					"open_by_handle_at", "open_tree", "perf_event_open", "pivot_root",
					"process_vm_readv", "process_vm_writev", "ptrace", "quotactl",
					"reboot", "request_key", "setns", "swapoff", "swapon",
					"sysfs", "umount", "umount2", "unshare", "userfaultfd",
				},
				Action:   specs.ActErrno,
				ErrnoRet: &errno,
			}},
		}
	}

	return specs.Spec{
		Version: specs.Version,
		Process: &specs.Process{
			Args:            append([]string(nil), options.Process.Args...),
			Env:             append([]string(nil), options.Process.Env...),
			Cwd:             options.Process.Cwd,
			Terminal:        false,
			NoNewPrivileges: features.NoNewPrivileges,
			User: specs.User{
				UID: options.Process.UID,
				GID: options.Process.GID,
			},
			Capabilities: &specs.LinuxCapabilities{},
		},
		Root: &specs.Root{Path: rootfsDirName, Readonly: features.ReadOnlyRootFS},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "noexec", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=" + strconv.FormatUint(diskBytes, 10)}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		},
		Annotations: map[string]string{"mysterium.runtime.service": options.Name},
		Linux:       linux,
	}, nil
}

func (backend *RuncBackend) loadServices() (map[string]Options, error) {
	data, err := os.ReadFile(backend.metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]Options), nil
		}
		return nil, errors.Wrap(err, "failed to read runtime metadata")
	}

	var persisted persistedServices
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, errors.Wrap(err, "failed to decode runtime metadata")
	}
	if persisted.SchemaVersion != metadataSchemaVersion {
		return nil, errors.Errorf(
			"unsupported runtime metadata schema %d; refusing to start legacy mutable definitions",
			persisted.SchemaVersion,
		)
	}
	if persisted.Services == nil {
		persisted.Services = make(map[string]Options)
	}
	for name, options := range persisted.Services {
		if name != options.Name {
			return nil, errors.Errorf("runtime metadata key %q does not match definition name %q", name, options.Name)
		}
		if err := validateStoredOptions(options); err != nil {
			return nil, errors.Wrapf(err, "invalid stored runtime definition %q", name)
		}
	}
	return persisted.Services, nil
}

func (backend *RuncBackend) persistLocked() error {
	persisted := persistedServices{
		SchemaVersion: metadataSchemaVersion,
		Services:      backend.services,
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to encode runtime metadata")
	}

	if err := os.WriteFile(backend.metadataPath, data, 0o600); err != nil {
		return errors.Wrap(err, "failed to write runtime metadata")
	}
	return nil
}

func validateStoredOptions(options Options) error {
	if err := validateServiceName(options.Name); err != nil {
		return err
	}
	if _, err := name.NewDigest(options.OCIArtifact, name.StrictValidation); err != nil {
		return errors.Wrap(err, "stored OCI artifact is not digest-pinned")
	}
	if len(options.Process.Args) == 0 || options.Process.UID == 0 || options.Process.GID == 0 {
		return errors.New("stored OCI process definition is incomplete or root")
	}
	if !filepath.IsAbs(options.Process.Cwd) || filepath.Clean(options.Process.Cwd) != options.Process.Cwd {
		return errors.New("stored OCI working directory is invalid")
	}
	if err := validateIsolationProfile(options.Isolation); err != nil {
		return errors.Wrap(err, "stored isolation profile is invalid")
	}
	minimumLevel, err := normalizeMinimumRuntimeLevel(options.MinimumRuntimeLevel)
	if err != nil || minimumLevel != options.MinimumRuntimeLevel {
		return errors.New("stored minimum runtime level is invalid")
	}
	if runtimeLevelRank(options.Isolation.Level) < runtimeLevelRank(minimumLevel) {
		return errors.New("stored isolation profile is below the required minimum runtime level")
	}
	var manifest Manifest
	manifest.SchemaVersion = 1
	manifest.Service.Protocol = "tcp"
	manifest.Service.InternalPort = options.ServicePort
	manifest.Resources = options.ResourceLimits
	_, err = validateManifest(manifest)
	return err
}

func validateIsolationProfile(profile IsolationProfile) error {
	if profile.Level != RuntimeLevelUnisolated &&
		profile.Level != RuntimeLevelLimited &&
		profile.Level != RuntimeLevelFull {
		return errors.Errorf("invalid runtime level %q", profile.Level)
	}
	if profile.Name != UnisolatedProfile &&
		profile.Name != BestEffortIsolationProfile &&
		profile.Name != FullIsolationProfile {
		return errors.Errorf("unknown profile %q", profile.Name)
	}
	if profile.Level == RuntimeLevelFull && profile.Name != FullIsolationProfile {
		return errors.New("full runtime level requires the full isolation profile")
	}
	if profile.Level == RuntimeLevelLimited && profile.Name != BestEffortIsolationProfile {
		return errors.New("limited runtime level requires the best-effort isolation profile")
	}
	if profile.Level == RuntimeLevelUnisolated && profile.Name != UnisolatedProfile {
		return errors.New("unisolated runtime level requires the unisolated profile")
	}
	if !profile.Features.FilesystemJail ||
		!profile.Features.NonRootUser ||
		!profile.Features.CapabilitiesDropped {
		return errors.New("isolation profile is missing mandatory execution safeguards")
	}
	if profile.Level == RuntimeLevelUnisolated {
		features := profile.Features
		if features.UserNamespaces || features.MountNamespaces || features.PIDNamespaces ||
			features.NetworkNamespaces || features.IPCNamespaces || features.Cgroups ||
			features.Seccomp || features.ReadOnlyRootFS {
			return errors.New("unisolated profile must not claim isolation features")
		}
		return nil
	}
	if !profile.Features.MountNamespaces {
		return errors.New("mount namespace is required")
	}
	if !profile.Features.NoNewPrivileges {
		return errors.New("no_new_privileges is required")
	}
	if profile.Level == RuntimeLevelFull && !hasFullIsolation(profile.Features) {
		return errors.New("full profile is missing isolation features")
	}
	return nil
}

func (backend *RuncBackend) bundleDir(name string) string {
	return filepath.Join(backend.bundlesDir, strings.ReplaceAll(name, string(os.PathSeparator), "_"))
}

func (backend *RuncBackend) containerID(name string) string {
	return name
}

func extractImageRootFS(
	img v1.Image,
	rootfsPath string,
	maxBytes uint64,
	uidMappings []specs.LinuxIDMapping,
	gidMappings []specs.LinuxIDMapping,
) error {
	stream := mutate.Extract(img)
	defer stream.Close()

	rootfsPath = filepath.Clean(rootfsPath)
	rootUID, ok := mapContainerID(uidMappings, 0)
	if !ok {
		return errors.New("subordinate UID mapping does not contain container root")
	}
	rootGID, ok := mapContainerID(gidMappings, 0)
	if !ok {
		return errors.New("subordinate GID mapping does not contain container root")
	}
	if err := os.Chown(rootfsPath, int(rootUID), int(rootGID)); err != nil {
		return errors.Wrap(err, "failed to map OCI rootfs ownership")
	}

	reader := tar.NewReader(stream)
	var extractedBytes uint64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.Wrap(err, "failed to read extracted OCI tar stream")
		}

		targetPath, err := secureJoinUnder(rootfsPath, header.Name)
		if err != nil {
			return errors.Wrapf(err, "invalid OCI tar entry path %q", header.Name)
		}
		if err := ensureNoSymlinkParents(rootfsPath, targetPath); err != nil {
			return errors.Wrapf(err, "unsafe OCI tar entry path %q", header.Name)
		}
		if header.Uid < 0 || header.Gid < 0 || uint64(header.Uid) > math.MaxUint32 || uint64(header.Gid) > math.MaxUint32 {
			return errors.Errorf("OCI tar entry %q has invalid ownership", header.Name)
		}
		hostUID, ok := mapContainerID(uidMappings, uint32(header.Uid))
		if !ok {
			return errors.Errorf("OCI tar entry %q UID %d is outside the subordinate mapping", header.Name, header.Uid)
		}
		hostGID, ok := mapContainerID(gidMappings, uint32(header.Gid))
		if !ok {
			return errors.Errorf("OCI tar entry %q GID %d is outside the subordinate mapping", header.Name, header.Gid)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return errors.Wrapf(err, "failed to create directory %q", targetPath)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || uint64(header.Size) > maxBytes-extractedBytes {
				return errors.Errorf("OCI rootfs exceeds %d bytes", maxBytes)
			}
			extractedBytes += uint64(header.Size)
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return errors.Wrapf(err, "failed to create parent directory for %q", targetPath)
			}
			if err := os.RemoveAll(targetPath); err != nil {
				return errors.Wrapf(err, "failed to replace rootfs file %q", targetPath)
			}
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return errors.Wrapf(err, "failed to create file %q", targetPath)
			}
			if _, err := io.Copy(file, reader); err != nil {
				file.Close()
				return errors.Wrapf(err, "failed to extract file %q", targetPath)
			}
			if err := file.Close(); err != nil {
				return errors.Wrapf(err, "failed to close file %q", targetPath)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return errors.Wrapf(err, "failed to create symlink parent for %q", targetPath)
			}
			symlinkTarget, err := secureSymlinkTarget(rootfsPath, targetPath, header.Linkname)
			if err != nil {
				return errors.Wrapf(err, "invalid symlink target %q for %q", header.Linkname, targetPath)
			}
			if err := os.RemoveAll(targetPath); err != nil {
				return errors.Wrapf(err, "failed to replace symlink target %q", targetPath)
			}
			if err := os.Symlink(symlinkTarget, targetPath); err != nil {
				return errors.Wrapf(err, "failed to create symlink %q", targetPath)
			}
		case tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return errors.Errorf("OCI rootfs entry %q uses forbidden file type %d", header.Name, header.Typeflag)
		default:
			return errors.Errorf("OCI rootfs entry %q uses unsupported file type %d", header.Name, header.Typeflag)
		}

		if err := os.Lchown(targetPath, int(hostUID), int(hostGID)); err != nil {
			return errors.Wrapf(err, "failed to map ownership for OCI tar entry %q", header.Name)
		}
		if header.Typeflag != tar.TypeSymlink {
			if err := os.Chtimes(targetPath, header.AccessTime, header.ModTime); err != nil && !os.IsNotExist(err) {
				return errors.Wrapf(err, "failed to update times for %q", targetPath)
			}
		}
	}
}

func processFromImage(config *v1.ConfigFile) (ProcessDefinition, error) {
	if config == nil {
		return ProcessDefinition{}, errors.New("OCI image config is required")
	}
	args := append([]string(nil), config.Config.Entrypoint...)
	args = append(args, config.Config.Cmd...)
	if len(args) == 0 {
		return ProcessDefinition{}, errors.New("OCI image must define Entrypoint or Cmd")
	}
	cwd := config.Config.WorkingDir
	if cwd == "" {
		cwd = "/"
	}
	if !filepath.IsAbs(cwd) || filepath.Clean(cwd) != cwd {
		return ProcessDefinition{}, errors.New("OCI image WorkingDir must be a clean absolute path")
	}
	uid, gid, err := parseImageUser(config.Config.User)
	if err != nil {
		return ProcessDefinition{}, err
	}
	return ProcessDefinition{
		Args: args,
		Env:  append([]string(nil), config.Config.Env...),
		Cwd:  cwd,
		UID:  uid,
		GID:  gid,
	}, nil
}

func parseImageUser(value string) (uint32, uint32, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 || strings.TrimSpace(value) == "" {
		return 0, 0, errors.New("OCI image must declare a numeric non-root user")
	}
	uid64, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || uid64 == 0 {
		return 0, 0, errors.New("OCI image user must be a numeric non-root UID")
	}
	gid64 := uid64
	if len(parts) == 2 {
		gid64, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil || gid64 == 0 {
			return 0, 0, errors.New("OCI image group must be a numeric non-root GID")
		}
	}
	return uint32(uid64), uint32(gid64), nil
}

func readManifest(rootfsPath string) (Manifest, error) {
	path := filepath.Join(rootfsPath, manifestFileName)
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, errors.Wrap(err, "OCI artifact is missing mysterium-runtime.json")
	}
	defer file.Close()
	var manifest Manifest
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, errors.Wrap(err, "invalid mysterium-runtime.json")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, errors.New("mysterium-runtime.json must contain one JSON object within 64 KiB")
	}
	return manifest, nil
}

func validateManifest(manifest Manifest) (ResourceLimits, error) {
	if manifest.SchemaVersion != 1 {
		return ResourceLimits{}, errors.Errorf("unsupported runtime manifest schema_version %d", manifest.SchemaVersion)
	}
	if strings.ToLower(manifest.Service.Protocol) != "tcp" {
		return ResourceLimits{}, errors.New("runtime manifest service protocol must be tcp")
	}
	if manifest.Service.InternalPort < 1 || manifest.Service.InternalPort > 65535 {
		return ResourceLimits{}, errors.New("runtime manifest internal_port must be between 1 and 65535")
	}
	limits := manifest.Resources
	if limits.CPU == "" {
		limits.CPU = "1"
	}
	if limits.Memory == "" {
		limits.Memory = "512MiB"
	}
	if limits.Disk == "" {
		limits.Disk = "512MiB"
	}
	if limits.Pids == 0 {
		limits.Pids = 128
	}
	cpu, err := strconv.ParseFloat(limits.CPU, 64)
	if err != nil || cpu <= 0 || cpu > 64 {
		return ResourceLimits{}, errors.New("runtime manifest CPU limit must be greater than 0 and at most 64")
	}
	if memory, ok := parseBytes(limits.Memory); !ok || memory < 16*1024*1024 || memory > 64*1024*1024*1024 {
		return ResourceLimits{}, errors.New("runtime manifest memory limit must be between 16MiB and 64GiB")
	}
	if disk, ok := parseBytes(limits.Disk); !ok || disk < 1024*1024 || disk > maxRootFSSize {
		return ResourceLimits{}, errors.New("runtime manifest disk limit must be between 1MiB and 1GiB")
	}
	if limits.Pids < 2 || limits.Pids > 4096 {
		return ResourceLimits{}, errors.New("runtime manifest pids limit must be between 2 and 4096")
	}
	return limits, nil
}

func buildLinuxResources(limits ResourceLimits) *specs.LinuxResources {
	resources := &specs.LinuxResources{}
	if cpu := buildLinuxCPU(limits.CPU); cpu != nil {
		resources.CPU = cpu
	}
	if memory := buildLinuxMemory(limits.Memory); memory != nil {
		resources.Memory = memory
	}
	pids := int64(limits.Pids)
	resources.Pids = &specs.LinuxPids{Limit: pids}
	return resources
}

func buildLinuxCPU(value string) *specs.LinuxCPU {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if cpus, ok := strings.CutPrefix(value, "cpuset="); ok {
		return &specs.LinuxCPU{Cpus: cpus}
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed <= 0 {
		return nil
	}

	quota := int64(math.Round(parsed * float64(defaultCPUPeriod)))
	period := defaultCPUPeriod
	return &specs.LinuxCPU{Quota: &quota, Period: &period}
}

func buildLinuxMemory(value string) *specs.LinuxMemory {
	bytes, ok := parseBytes(value)
	if !ok {
		return nil
	}
	limit := int64(bytes)
	return &specs.LinuxMemory{Limit: &limit}
}

func parseBytes(value string) (uint64, bool) {
	value = strings.TrimSpace(strings.ToUpper(value))
	if value == "" {
		return 0, false
	}

	multiplier := uint64(1)
	for _, unit := range []struct {
		suffix string
		mul    uint64
	}{
		{"KIB", 1024},
		{"MIB", 1024 * 1024},
		{"GIB", 1024 * 1024 * 1024},
		{"TIB", 1024 * 1024 * 1024 * 1024},
		{"KB", 1000},
		{"MB", 1000 * 1000},
		{"GB", 1000 * 1000 * 1000},
		{"TB", 1000 * 1000 * 1000 * 1000},
		{"B", 1},
	} {
		if strings.HasSuffix(value, unit.suffix) {
			multiplier = unit.mul
			value = strings.TrimSpace(strings.TrimSuffix(value, unit.suffix))
			break
		}
	}

	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 {
		return 0, false
	}

	return uint64(math.Round(parsed * float64(multiplier))), true
}

func isContainerMissingError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "does not exist") || strings.Contains(message, "not found")
}

func (backend *RuncBackend) wrapRuncError(operation, containerName string, err error) error {
	base := errors.Wrapf(err, "failed to %s runc container %q", operation, containerName)

	logSnippet := backend.recentRuncLogLines(40)
	if logSnippet == "" {
		return base
	}

	return errors.Wrap(base, "recent runc log:\n"+logSnippet)
}

func (backend *RuncBackend) recentRuncLogLines(maxLines int) string {
	if backend == nil || backend.runc == nil || backend.runc.Log == "" || maxLines <= 0 {
		return ""
	}

	data, err := os.ReadFile(backend.runc.Log)
	if err != nil || len(data) == 0 {
		return ""
	}

	lines := bytes.Split(data, []byte{'\n'})
	start := 0
	if len(lines) > maxLines {
		start = len(lines) - maxLines
	}

	snippet := strings.TrimSpace(string(bytes.Join(lines[start:], []byte{'\n'})))
	return snippet
}

func canCreateRuncCgroupPath(name string) error {
	cleanName := filepath.Clean(strings.TrimSpace(name))
	if cleanName == "" || cleanName == "." {
		return errors.New("empty container name for cgroup path")
	}
	if filepath.IsAbs(cleanName) {
		return errors.Errorf("invalid absolute cgroup path %q", name)
	}
	if cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
		return errors.Errorf("invalid cgroup path traversal %q", name)
	}

	target := filepath.Join("/sys/fs/cgroup", cleanName)
	if !isPathWithinRoot("/sys/fs/cgroup", target) {
		return errors.Errorf("invalid cgroup target path %q", cleanName)
	}

	err := os.Mkdir(target, 0o755)
	if err == nil {
		_ = os.Remove(target)
		return nil
	}
	if os.IsExist(err) {
		return nil
	}
	return err
}

func validateServiceName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("runtime service name is required")
	}
	if strings.TrimSpace(name) != name {
		return errors.New("runtime service name must not contain leading or trailing whitespace")
	}
	if len(name) > maxServiceNameLength {
		return errors.Errorf("runtime service name exceeds %d characters", maxServiceNameLength)
	}
	if !serviceNamePattern.MatchString(name) {
		return errors.New("runtime service name may contain only letters, numbers, dot, underscore, and dash")
	}
	if name == "." || name == ".." {
		return errors.New("runtime service name must not be dot or dot-dot")
	}
	return nil
}

func inspectRuntimeHost() runtimeHostChecks {
	checks := runtimeHostChecks{
		effectiveCapabilities: make(map[uint]bool, len(runtimeCapabilityRequirements)),
	}
	if _, err := exec.LookPath(runc.DefaultCommand); err == nil {
		checks.runcAvailable = true
	}
	for _, capability := range runtimeCapabilityRequirements {
		checks.effectiveCapabilities[capability.bit] = hasEffectiveCapability(capability.bit)
	}
	if _, _, err := loadUserMappings(); err == nil {
		checks.userMappingsAvailable = true
	}
	if err := requireDelegatedCgroupControllers("cpu", "memory", "pids"); err == nil {
		checks.cgroupControllersAvailable = true
	}
	return checks
}

func requireDelegatedCgroupControllers(required ...string) error {
	_, root, err := delegatedCgroupParent()
	if err != nil {
		return err
	}
	enabledData, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		return errors.Wrap(err, "cannot read delegated cgroup controllers")
	}
	enabled := make(map[string]struct{})
	for _, controller := range strings.Fields(string(enabledData)) {
		enabled[strings.TrimPrefix(controller, "+")] = struct{}{}
	}
	var missing []string
	for _, controller := range required {
		if _, ok := enabled[controller]; !ok {
			missing = append(missing, controller)
		}
	}
	if len(missing) > 0 {
		return errors.Errorf("delegated cgroup controllers are not enabled: %s", strings.Join(missing, ", "))
	}
	return nil
}

func delegatedCgroupParent() (string, string, error) {
	currentPath := strings.TrimSpace(os.Getenv(cgroupParentEnv))
	if currentPath == "" {
		data, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			return "", "", errors.Wrap(err, "cannot read current cgroup")
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "0::") {
				currentPath = strings.TrimSpace(strings.TrimPrefix(line, "0::"))
				break
			}
		}
	}
	if currentPath == "" || !filepath.IsAbs(currentPath) {
		return "", "", errors.Errorf("invalid delegated cgroup parent %q", currentPath)
	}

	currentPath = filepath.Clean(currentPath)
	root := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(currentPath, "/"))
	if !isPathWithinRoot("/sys/fs/cgroup", root) {
		return "", "", errors.Errorf("delegated cgroup parent %q escapes cgroup v2", currentPath)
	}
	return currentPath, root, nil
}

func hasEffectiveCapability(bit uint) bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		return err == nil && value&(uint64(1)<<bit) != 0
	}
	return false
}

func loadUserMappings() ([]specs.LinuxIDMapping, []specs.LinuxIDMapping, error) {
	current, err := user.Current()
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot identify runtime user for subordinate mappings")
	}
	uid, err := readSubIDMapping("/etc/subuid", current.Username, strconv.Itoa(os.Geteuid()))
	if err != nil {
		return nil, nil, err
	}
	gid, err := readSubIDMapping("/etc/subgid", current.Username, strconv.Itoa(os.Getegid()))
	if err != nil {
		return nil, nil, err
	}
	return []specs.LinuxIDMapping{uid}, []specs.LinuxIDMapping{gid}, nil
}

func readSubIDMapping(path, owner, numericOwner string) (specs.LinuxIDMapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return specs.LinuxIDMapping{}, errors.Wrapf(err, "cannot read %s", path)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) != 3 || (parts[0] != owner && parts[0] != numericOwner) {
			continue
		}
		start, startErr := strconv.ParseUint(parts[1], 10, 32)
		size, sizeErr := strconv.ParseUint(parts[2], 10, 32)
		if startErr == nil && sizeErr == nil && size >= 65536 {
			return specs.LinuxIDMapping{ContainerID: 0, HostID: uint32(start), Size: uint32(size)}, nil
		}
	}
	return specs.LinuxIDMapping{}, errors.Errorf("%s has no subordinate range of at least 65536 IDs for %s", path, owner)
}

func mappingContains(mappings []specs.LinuxIDMapping, id uint32) bool {
	for _, mapping := range mappings {
		if id >= mapping.ContainerID && uint64(id) < uint64(mapping.ContainerID)+uint64(mapping.Size) {
			return true
		}
	}
	return false
}

func mapContainerID(mappings []specs.LinuxIDMapping, id uint32) (uint32, bool) {
	for _, mapping := range mappings {
		if id < mapping.ContainerID || uint64(id) >= uint64(mapping.ContainerID)+uint64(mapping.Size) {
			continue
		}
		hostID := uint64(mapping.HostID) + uint64(id-mapping.ContainerID)
		if hostID > math.MaxUint32 {
			return 0, false
		}
		return uint32(hostID), true
	}
	return 0, false
}

func rootFSOwnershipMappings(
	profile IsolationProfile,
) ([]specs.LinuxIDMapping, []specs.LinuxIDMapping, error) {
	if profile.Features.UserNamespaces {
		return loadUserMappings()
	}

	// Without a user namespace, OCI IDs are host IDs. The maximum uint32 ID
	// cannot be represented as the end of an OCI mapping and is intentionally
	// excluded.
	identity := []specs.LinuxIDMapping{{
		ContainerID: 0,
		HostID:      0,
		Size:        math.MaxUint32,
	}}
	return identity, identity, nil
}

func ensureNoSymlinkParents(root, target string) error {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("path escapes rootfs")
	}
	current := filepath.Clean(root)
	parts := strings.Split(rel, string(os.PathSeparator))
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.Errorf("parent %q is a symlink", current)
		}
	}
	return nil
}

func cgroupPathForService(name string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '.', r == '_', r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	parent, _, err := delegatedCgroupParent()
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, "mysterium-"+builder.String()), nil
}

func secureJoinUnder(root, tarPath string) (string, error) {
	if strings.ContainsRune(tarPath, '\x00') {
		return "", errors.New("path contains NUL byte")
	}

	cleanRel := filepath.Clean(filepath.FromSlash(tarPath))
	if cleanRel == "." || cleanRel == "" {
		return "", errors.New("path resolves to root")
	}
	if filepath.IsAbs(cleanRel) {
		return "", errors.New("absolute paths are not allowed")
	}

	target := filepath.Join(root, cleanRel)
	if !isPathWithinRoot(root, target) {
		return "", errors.New("path escapes rootfs")
	}
	return target, nil
}

func secureSymlinkTarget(root, linkPath, linkTarget string) (string, error) {
	if strings.ContainsRune(linkTarget, '\x00') {
		return "", errors.New("symlink target contains NUL byte")
	}

	filesystemTarget := filepath.FromSlash(linkTarget)
	if filepath.IsAbs(filesystemTarget) {
		containerTarget := strings.TrimPrefix(filepath.Clean(filesystemTarget), string(os.PathSeparator))
		resolved := filepath.Join(root, containerTarget)
		if !isPathWithinRoot(root, resolved) {
			return "", errors.New("symlink target escapes rootfs")
		}

		relativeTarget, err := filepath.Rel(filepath.Dir(linkPath), resolved)
		if err != nil {
			return "", errors.Wrap(err, "failed to rewrite absolute symlink target")
		}
		return relativeTarget, nil
	}

	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), filesystemTarget))
	if !isPathWithinRoot(root, resolved) {
		return "", errors.New("symlink target escapes rootfs")
	}
	return filesystemTarget, nil
}

func isPathWithinRoot(root, candidate string) bool {
	cleanRoot := filepath.Clean(root)
	cleanCandidate := filepath.Clean(candidate)
	rel, err := filepath.Rel(cleanRoot, cleanCandidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
