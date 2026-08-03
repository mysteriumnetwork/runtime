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
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type namespaceResult struct {
	socketFD int
	err      error
}

func canEnterCurrentNetworkNamespace() bool {
	result := runInNetworkNamespace(os.Getpid(), func() (int, error) {
		return -1, nil
	})
	return result.err == nil
}

func configureLoopback(pid int) error {
	result := runInNetworkNamespace(pid, func() (int, error) {
		socketFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return -1, errors.Wrap(err, "failed to create loopback configuration socket")
		}
		defer unix.Close(socketFD)

		addressRequest, err := unix.NewIfreq("lo")
		if err != nil {
			return -1, errors.Wrap(err, "failed to create loopback address request")
		}
		if err := addressRequest.SetInet4Addr([]byte{127, 0, 0, 1}); err != nil {
			return -1, errors.Wrap(err, "failed to set loopback address")
		}
		if err := unix.IoctlIfreq(socketFD, unix.SIOCSIFADDR, addressRequest); err != nil {
			return -1, errors.Wrap(err, "failed to configure loopback address")
		}

		netmaskRequest, err := unix.NewIfreq("lo")
		if err != nil {
			return -1, errors.Wrap(err, "failed to create loopback netmask request")
		}
		if err := netmaskRequest.SetInet4Addr([]byte{255, 0, 0, 0}); err != nil {
			return -1, errors.Wrap(err, "failed to set loopback netmask")
		}
		if err := unix.IoctlIfreq(socketFD, unix.SIOCSIFNETMASK, netmaskRequest); err != nil {
			return -1, errors.Wrap(err, "failed to configure loopback netmask")
		}

		request, err := unix.NewIfreq("lo")
		if err != nil {
			return -1, errors.Wrap(err, "failed to create loopback interface request")
		}
		if err := unix.IoctlIfreq(socketFD, unix.SIOCGIFFLAGS, request); err != nil {
			return -1, errors.Wrap(err, "failed to read loopback interface flags")
		}
		request.SetUint16(request.Uint16() | unix.IFF_UP)
		if err := unix.IoctlIfreq(socketFD, unix.SIOCSIFFLAGS, request); err != nil {
			return -1, errors.Wrap(err, "failed to enable loopback interface")
		}

		return -1, nil
	})
	return result.err
}

func dialTCPInNamespace(pid, port int) (net.Conn, error) {
	result := runInNetworkNamespace(pid, func() (int, error) {
		socketFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return -1, errors.Wrap(err, "failed to create workload TCP socket")
		}

		address := &unix.SockaddrInet4{
			Port: port,
			Addr: [4]byte{127, 0, 0, 1},
		}
		if err := unix.Connect(socketFD, address); err != nil {
			unix.Close(socketFD)
			return -1, errors.Wrap(err, "failed to connect to workload TCP service")
		}
		return socketFD, nil
	})
	if result.err != nil {
		return nil, result.err
	}

	file := os.NewFile(uintptr(result.socketFD), "runtime-workload-tcp")
	if file == nil {
		unix.Close(result.socketFD)
		return nil, errors.New("failed to wrap workload TCP socket")
	}
	connection, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create workload TCP connection")
	}
	return connection, nil
}

// runInNetworkNamespace executes operation on a dedicated locked OS thread.
// If restoring the original namespace fails, the goroutine deliberately exits
// without unlocking so Go discards the contaminated OS thread.
func runInNetworkNamespace(pid int, operation func() (int, error)) namespaceResult {
	resultChannel := make(chan namespaceResult, 1)

	go func() {
		runtime.LockOSThread()

		originalFD, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			resultChannel <- namespaceResult{socketFD: -1, err: errors.Wrap(err, "failed to open current network namespace")}
			return
		}
		defer unix.Close(originalFD)

		targetPath := fmt.Sprintf("/proc/%d/ns/net", pid)
		targetFD, err := unix.Open(targetPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			resultChannel <- namespaceResult{
				socketFD: -1,
				err: errors.Wrap(
					err,
					"failed to open workload network namespace (requires CAP_SYS_PTRACE and outer /proc access)",
				),
			}
			return
		}
		defer unix.Close(targetFD)

		if err := unix.Setns(targetFD, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			resultChannel <- namespaceResult{socketFD: -1, err: errors.Wrap(err, "failed to enter workload network namespace")}
			return
		}

		socketFD, operationErr := operation()
		result := namespaceResult{socketFD: socketFD, err: operationErr}
		if restoreErr := unix.Setns(originalFD, unix.CLONE_NEWNET); restoreErr != nil {
			if result.socketFD >= 0 {
				unix.Close(result.socketFD)
			}
			resultChannel <- namespaceResult{
				socketFD: -1,
				err:      errors.Wrap(restoreErr, "failed to restore current network namespace"),
			}
			return
		}

		runtime.UnlockOSThread()
		resultChannel <- result
	}()

	return <-resultChannel
}
