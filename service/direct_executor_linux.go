//go:build linux

package service

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	directInitArgument   = "--mysterium-runtime-direct-init"
	directLaunchFileName = "direct-launch.json"
	directStateFileName  = "direct-state.json"
	directHandshakeFD    = 3
	directNullFD         = 4
	directStartTimeout   = 10 * time.Second
)

type directLaunchConfig struct {
	RootFS          string            `json:"rootfs"`
	Process         ProcessDefinition `json:"process"`
	NoNewPrivileges bool              `json:"no_new_privileges"`
}

type directProcessState struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
}

// The direct executor re-execs the runtime binary so the child can chroot and
// drop credentials immediately before replacing itself with the workload.
func init() {
	if len(os.Args) != 3 || os.Args[1] != directInitArgument {
		return
	}
	if err := runDirectInit(os.Args[2]); err != nil {
		if handshake := os.NewFile(directHandshakeFD, "direct-handshake"); handshake != nil {
			_, _ = fmt.Fprint(handshake, err.Error())
		}
		os.Exit(127)
	}
	panic("direct init returned after exec")
}

func runDirectInit(configPath string) error {
	runtime.LockOSThread()

	if !filepath.IsAbs(configPath) {
		return errors.New("direct launch config path must be absolute")
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		return errors.Wrap(err, "cannot inspect direct launch config")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxManifestSize {
		return errors.New("direct launch config is not a secure regular file")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return errors.Wrap(err, "cannot read direct launch config")
	}
	var config directLaunchConfig
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return errors.Wrap(err, "cannot decode direct launch config")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("direct launch config must contain exactly one JSON object")
	}
	if len(config.Process.Args) == 0 {
		return errors.New("direct process has no executable")
	}
	if config.Process.UID == 0 || config.Process.GID == 0 {
		return errors.New("direct process must use a numeric non-root UID and GID")
	}
	if !filepath.IsAbs(config.RootFS) ||
		filepath.Clean(config.RootFS) != config.RootFS ||
		!filepath.IsAbs(config.Process.Cwd) ||
		filepath.Clean(config.Process.Cwd) != config.Process.Cwd {
		return errors.New("direct rootfs and working directory must be clean absolute paths")
	}
	rootInfo, err := os.Stat(config.RootFS)
	if err != nil || !rootInfo.IsDir() {
		return errors.New("direct rootfs is not a directory")
	}

	if _, err := unix.FcntlInt(uintptr(directHandshakeFD), unix.F_GETFD, 0); err != nil {
		return errors.Wrap(err, "direct handshake descriptor is unavailable")
	}
	unix.CloseOnExec(directHandshakeFD)

	if err := unix.Dup2(directNullFD, unix.Stdin); err != nil {
		return errors.Wrap(err, "cannot connect direct stdin")
	}
	if err := unix.Dup2(directNullFD, unix.Stdout); err != nil {
		return errors.Wrap(err, "cannot connect direct stdout")
	}
	if err := unix.Dup2(directNullFD, unix.Stderr); err != nil {
		return errors.Wrap(err, "cannot connect direct stderr")
	}
	_ = unix.Close(directNullFD)

	if config.NoNewPrivileges {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return errors.Wrap(err, "cannot set no_new_privileges")
		}
	}
	if err := unix.Chroot(config.RootFS); err != nil {
		return errors.Wrap(err, "cannot enter direct rootfs")
	}
	if err := unix.Chdir(config.Process.Cwd); err != nil {
		return errors.Wrap(err, "cannot enter direct working directory")
	}
	if err := unix.Setgroups(nil); err != nil {
		return errors.Wrap(err, "cannot clear supplementary groups")
	}
	if err := unix.Setresgid(int(config.Process.GID), int(config.Process.GID), int(config.Process.GID)); err != nil {
		return errors.Wrap(err, "cannot drop direct process GID")
	}
	if err := unix.Setresuid(int(config.Process.UID), int(config.Process.UID), int(config.Process.UID)); err != nil {
		return errors.Wrap(err, "cannot drop direct process UID")
	}
	capabilities := [2]unix.CapUserData{}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capset(&header, &capabilities[0]); err != nil {
		return errors.Wrap(err, "cannot clear direct process capabilities")
	}

	executable, err := resolveDirectExecutable(config.Process.Args[0], config.Process.Cwd, config.Process.Env)
	if err != nil {
		return err
	}
	return unix.Exec(executable, config.Process.Args, config.Process.Env)
}

func resolveDirectExecutable(argument, cwd string, environment []string) (string, error) {
	if strings.ContainsRune(argument, '/') {
		candidate := argument
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
		if err := unix.Access(candidate, unix.X_OK); err != nil {
			return "", errors.Wrapf(err, "direct executable %q is unavailable", argument)
		}
		return candidate, nil
	}

	pathValue := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, entry := range environment {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			pathValue = value
			break
		}
	}
	for _, directory := range filepath.SplitList(pathValue) {
		if directory == "" {
			directory = cwd
		} else if !filepath.IsAbs(directory) {
			directory = filepath.Join(cwd, directory)
		}
		candidate := filepath.Join(directory, argument)
		if unix.Access(candidate, unix.X_OK) == nil {
			return candidate, nil
		}
	}
	return "", errors.Errorf("direct executable %q was not found in PATH", argument)
}

func startDirectProcess(configPath string) (*os.Process, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.Wrap(err, "cannot locate runtime executable")
	}
	handshakeReader, handshakeWriter, err := os.Pipe()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create direct start handshake")
	}
	defer handshakeReader.Close()

	nullFile, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		handshakeWriter.Close()
		return nil, errors.Wrap(err, "cannot open null device")
	}

	command := exec.Command(executable, directInitArgument, configPath)
	command.Env = []string{}
	command.ExtraFiles = []*os.File{handshakeWriter, nullFile}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		handshakeWriter.Close()
		nullFile.Close()
		return nil, errors.Wrap(err, "cannot start built-in direct executor")
	}
	handshakeWriter.Close()
	nullFile.Close()

	result := make(chan []byte, 1)
	go func() {
		message, _ := io.ReadAll(io.LimitReader(handshakeReader, maxManifestSize))
		result <- message
	}()

	select {
	case message := <-result:
		if len(message) != 0 {
			_, _ = command.Process.Wait()
			return nil, errors.Errorf("built-in direct executor failed: %s", strings.TrimSpace(string(message)))
		}
		return command.Process, nil
	case <-time.After(directStartTimeout):
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_, _ = command.Process.Wait()
		return nil, errors.New("built-in direct executor start timed out")
	}
}

func directProcessIdentity(pid int) (directProcessState, bool) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return directProcessState{}, false
	}
	end := strings.LastIndex(string(data), ") ")
	if end < 0 {
		return directProcessState{}, false
	}
	fields := strings.Fields(string(data)[end+2:])
	if len(fields) <= 19 || fields[0] == "Z" {
		return directProcessState{}, false
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return directProcessState{}, false
	}
	return directProcessState{PID: pid, StartTime: startTime}, true
}

func directProcessMatches(state directProcessState) bool {
	current, ok := directProcessIdentity(state.PID)
	return ok && state.PID > 1 && current.StartTime == state.StartTime
}

func readDirectState(path string) (directProcessState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return directProcessState{}, err
	}
	var state directProcessState
	if err := json.Unmarshal(data, &state); err != nil {
		return directProcessState{}, errors.Wrap(err, "invalid direct process state")
	}
	if state.PID <= 1 || state.StartTime == 0 {
		return directProcessState{}, errors.New("invalid direct process identity")
	}
	return state, nil
}

func writeSecureJSON(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (backend *RuncBackend) directStatePath(name string) string {
	return filepath.Join(backend.bundleDir(name), directStateFileName)
}

func (backend *RuncBackend) directStateLocked(name string) (*directProcessState, error) {
	path := backend.directStatePath(name)
	state, err := readDirectState(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read direct process state for %q", name)
	}
	if !directProcessMatches(state) {
		_ = os.Remove(path)
		return nil, nil
	}
	return &state, nil
}

func (backend *RuncBackend) startDirectLocked(options Options) error {
	if running, err := backend.directStateLocked(options.Name); err != nil {
		return err
	} else if running != nil {
		return nil
	}
	for name, candidate := range backend.services {
		if name == options.Name || candidate.Isolation.Level != RuntimeLevelUnisolated {
			continue
		}
		if running, err := backend.directStateLocked(name); err != nil {
			return err
		} else if running != nil {
			return errors.Errorf(
				"unisolated runtime service %q is already active; direct execution permits one workload at a time",
				name,
			)
		}
	}

	bundleDir := backend.bundleDir(options.Name)
	launchPath := filepath.Join(bundleDir, directLaunchFileName)
	config := directLaunchConfigForOptions(options, filepath.Join(bundleDir, rootfsDirName))
	if err := writeSecureJSON(launchPath, config); err != nil {
		return errors.Wrapf(err, "cannot prepare direct runtime service %q", options.Name)
	}

	process, err := startDirectProcess(launchPath)
	if err != nil {
		return errors.Wrapf(err, "cannot start unisolated runtime service %q", options.Name)
	}
	state, ok := directProcessIdentity(process.Pid)
	if !ok {
		_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
		_, _ = process.Wait()
		return errors.Errorf("unisolated runtime service %q exited during start", options.Name)
	}
	if err := writeSecureJSON(backend.directStatePath(options.Name), state); err != nil {
		_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
		_, _ = process.Wait()
		return errors.Wrapf(err, "cannot persist direct process state for %q", options.Name)
	}
	// Reap the child when the backend lives longer than the workload. If this
	// one-shot CLI process exits first, the kernel reparents the workload.
	go func() {
		_, _ = process.Wait()
	}()
	return nil
}

func directLaunchConfigForOptions(options Options, rootfs string) directLaunchConfig {
	config := directLaunchConfig{
		RootFS:          rootfs,
		Process:         options.Process,
		NoNewPrivileges: options.Isolation.Features.NoNewPrivileges,
	}
	config.Process.Env = processEnvironment(options)
	return config
}

func (backend *RuncBackend) stopDirectLocked(name string) error {
	path := backend.directStatePath(name)
	state, err := readDirectState(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.Wrapf(err, "cannot safely stop direct runtime service %q", name)
	}
	if !directProcessMatches(state) {
		_ = os.Remove(path)
		return nil
	}

	if err := syscall.Kill(-state.PID, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return errors.Wrapf(err, "cannot terminate direct runtime service %q", name)
	}
	deadline := time.Now().Add(stopTimeout)
	for time.Now().Before(deadline) {
		if !directProcessMatches(state) {
			_ = os.Remove(path)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if directProcessMatches(state) {
		if err := syscall.Kill(-state.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return errors.Wrapf(err, "cannot kill direct runtime service %q", name)
		}
	}
	killDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(killDeadline) {
		if !directProcessMatches(state) {
			_ = os.Remove(path)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.Errorf("direct runtime service %q remained active after SIGKILL", name)
}

func probeDirectExecutor(baseDir string, noNewPrivileges bool) (bool, string) {
	executable := ""
	for _, candidate := range []string{"/usr/bin/true", "/bin/true"} {
		if unix.Access(candidate, unix.X_OK) == nil {
			executable = candidate
			break
		}
	}
	if executable == "" {
		return false, "built-in direct executor probe requires /bin/true or /usr/bin/true"
	}
	probePath := filepath.Join(baseDir, ".direct-executor-probe.json")
	config := directLaunchConfig{
		RootFS: "/",
		Process: ProcessDefinition{
			Args: []string{executable},
			Env:  []string{"PATH=/usr/bin:/bin"},
			Cwd:  "/",
			UID:  65534,
			GID:  65534,
		},
		NoNewPrivileges: noNewPrivileges,
	}
	if err := writeSecureJSON(probePath, config); err != nil {
		return false, "cannot prepare built-in direct executor probe: " + err.Error()
	}
	defer os.Remove(probePath)
	process, err := startDirectProcess(probePath)
	if err != nil {
		return false, err.Error()
	}
	state, err := process.Wait()
	if err != nil || !state.Success() {
		if err != nil {
			return false, "built-in direct executor probe failed: " + err.Error()
		}
		return false, "built-in direct executor probe exited unsuccessfully"
	}
	return true, ""
}
