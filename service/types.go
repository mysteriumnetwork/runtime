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

// Backend defines runtime service lifecycle operations.
type Backend interface {
	Create(options CreateOptions) error
	Delete(name string) error
	Start(name string) error
	Stop(name string) error
	DialTCP(name string, port int) (net.Conn, error)
	List() ([]ServiceInfo, error)
	Availability() (bool, string)
	Capabilities() (capabilities.RuntimeCapabilities, capabilities.DetailedCapabilities)
}
