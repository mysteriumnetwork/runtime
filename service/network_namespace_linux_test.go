//go:build linux

package service

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDialTCPInCurrentNetworkNamespace(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer connection.Close()

		message := make([]byte, len("ping"))
		if _, readErr := io.ReadFull(connection, message); readErr != nil {
			accepted <- readErr
			return
		}
		_, writeErr := connection.Write([]byte("pong"))
		accepted <- writeErr
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	connection, err := dialTCPInNamespace(os.Getpid(), port)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("network namespace switching is not permitted: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("pong"))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("unexpected response: %q", response)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestRunInNetworkNamespaceRejectsMissingProcess(t *testing.T) {
	result := runInNetworkNamespace(-1, func() (int, error) {
		t.Fatal("operation must not run")
		return -1, nil
	})
	if result.err == nil {
		t.Fatal("expected missing network namespace to fail")
	}
}
