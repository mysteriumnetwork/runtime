package service

import (
	"net"

	"github.com/mysteriumnetwork/runtime/capabilities"
)

// ServiceState represents whether a runtime-defined service is active or passive.
type ServiceState string

const (
	ServiceStateActive  ServiceState = "active"
	ServiceStatePassive ServiceState = "passive"
)

// ServiceInfo describes a runtime-defined service known to the backend.
type ServiceInfo struct {
	Name    string       `json:"name"`
	State   ServiceState `json:"state"`
	Options Options      `json:"options,omitempty"`
}

// RuntimeLevel describes whether workloads can run and how completely the
// runtime can isolate them.
type RuntimeLevel string

const (
	RuntimeLevelUnavailable RuntimeLevel = "unavailable"
	RuntimeLevelUnisolated  RuntimeLevel = "unisolated"
	RuntimeLevelLimited     RuntimeLevel = "limited"
	RuntimeLevelFull        RuntimeLevel = "full"
)

const (
	FullIsolationProfile       = "full-v1"
	BestEffortIsolationProfile = "best-effort-v1"
	UnisolatedProfile          = "unisolated-v1"
)

// IsolationFeatures records the isolation mechanisms that an execution
// profile actually applies. It is deliberately separate from host capability
// detection: detected features are facts about the host, while these features
// are the guarantees made for a workload.
type IsolationFeatures struct {
	FilesystemJail      bool `json:"filesystem_jail"`
	NonRootUser         bool `json:"non_root_user"`
	CapabilitiesDropped bool `json:"capabilities_dropped"`
	UserNamespaces      bool `json:"user_namespaces"`
	MountNamespaces     bool `json:"mount_namespaces"`
	PIDNamespaces       bool `json:"pid_namespaces"`
	NetworkNamespaces   bool `json:"network_namespaces"`
	IPCNamespaces       bool `json:"ipc_namespaces"`
	Cgroups             bool `json:"cgroups"`
	Seccomp             bool `json:"seccomp"`
	NoNewPrivileges     bool `json:"no_new_privileges"`
	ReadOnlyRootFS      bool `json:"read_only_rootfs"`
}

// IsolationProfile is the concrete, versioned execution plan selected for a
// workload.
type IsolationProfile struct {
	Name     string            `json:"name"`
	Level    RuntimeLevel      `json:"level"`
	Features IsolationFeatures `json:"features"`
}

// RuntimeStatus is the scheduler-facing assessment of this runtime.
// MissingForFull explains why an otherwise usable runtime is limited, while
// BlockingReasons explains why no workload can be spawned. Notices report
// recovered faults that did not block startup but that an operator should see,
// such as runtime definitions discarded during metadata recovery.
type RuntimeStatus struct {
	Level             RuntimeLevel     `json:"level"`
	Profile           IsolationProfile `json:"profile"`
	FullProfile       string           `json:"full_profile"`
	LimitedProfile    string           `json:"limited_profile"`
	UnisolatedProfile string           `json:"unisolated_profile"`
	MissingForLimited []string         `json:"missing_for_limited,omitempty"`
	MissingForFull    []string         `json:"missing_for_full,omitempty"`
	BlockingReasons   []string         `json:"blocking_reasons,omitempty"`
	Notices           []string         `json:"notices,omitempty"`
}

// Backend defines runtime service lifecycle operations.
type Backend interface {
	Create(options CreateOptions) error
	Delete(name string) error
	Start(name string) error
	Stop(name string) error
	DialTCP(name string, port int) (net.Conn, error)
	List() ([]ServiceInfo, error)
	Status() RuntimeStatus
	Availability() (bool, string)
	Capabilities() (capabilities.RuntimeCapabilities, capabilities.DetailedCapabilities)
}
