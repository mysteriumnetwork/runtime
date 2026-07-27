//go:build !linux

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
	"net"

	"github.com/mysteriumnetwork/runtime/capabilities"
	"github.com/pkg/errors"
)

type unsupportedBackend struct{}

// NewBackend creates the default runtime backend implementation.
func NewBackend(runtimeDir string) Backend {
	return &unsupportedBackend{}
}

func (backend *unsupportedBackend) Create(options CreateOptions) error {
	return errors.New("runc runtime backend is supported only on linux")
}

func (backend *unsupportedBackend) Delete(name string) error {
	return errors.New("runc runtime backend is supported only on linux")
}

func (backend *unsupportedBackend) Start(name string) error {
	return errors.New("runc runtime backend is supported only on linux")
}

func (backend *unsupportedBackend) Stop(name string) error {
	return errors.New("runc runtime backend is supported only on linux")
}

func (backend *unsupportedBackend) Availability() (bool, string) {
	return false, "runc runtime backend is supported only on linux"
}

func (backend *unsupportedBackend) DialTCP(name string, port int) (net.Conn, error) {
	return nil, errors.New("runtime workload TCP dialing is supported only on linux")
}

func (backend *unsupportedBackend) List() ([]ServiceInfo, error) {
	return nil, nil
}

func (backend *unsupportedBackend) Capabilities() (capabilities.RuntimeCapabilities, capabilities.DetailedCapabilities) {
	return capabilities.Detect()
}
