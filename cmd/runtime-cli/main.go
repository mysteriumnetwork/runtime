package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/mysteriumnetwork/runtime/capabilities"
	"github.com/mysteriumnetwork/runtime/service"
)

type capabilitiesOutput struct {
	Capabilities capabilities.RuntimeCapabilities  `json:"capabilities"`
	Detailed     capabilities.DetailedCapabilities `json:"detailed"`
	Runtime      service.RuntimeStatus             `json:"runtime"`
}

func main() {
	runtimeDir := flag.String("runtime-dir", "/tmp/myst-runtime", "runtime data directory")
	command := flag.String("command", "", "command: list|capabilities|status|create|delete|start|stop|proxy")
	name := flag.String("name", "", "service name")
	artifact := flag.String("oci-artifact", "", "OCI artifact reference")
	minimumRuntimeLevel := flag.String(
		"minimum-runtime-level",
		string(service.RuntimeLevelLimited),
		"minimum runtime level for create: unisolated|limited|full",
	)
	listen := flag.String("listen", "127.0.0.1:3000", "TCP listen address for the proxy command")
	flag.Parse()

	if strings.TrimSpace(*command) == "" {
		fmt.Fprintln(os.Stderr, "command is required")
		os.Exit(1)
	}

	backend := service.NewBackend(*runtimeDir)

	options := service.CreateOptions{
		Name:                *name,
		OCIArtifact:         *artifact,
		MinimumRuntimeLevel: service.RuntimeLevel(*minimumRuntimeLevel),
	}

	var err error
	switch *command {
	case "list":
		var services []service.ServiceInfo
		services, err = backend.List()
		if err == nil {
			printJSON(services)
		}
	case "capabilities":
		caps, detailed := backend.Capabilities()
		printJSON(capabilitiesOutput{
			Capabilities: caps,
			Detailed:     detailed,
			Runtime:      backend.Status(),
		})
	case "status":
		printJSON(backend.Status())
	case "create":
		err = backend.Create(options)
	case "delete":
		err = backend.Delete(*name)
	case "start":
		err = backend.Start(*name)
	case "stop":
		err = backend.Stop(*name)
	case "proxy":
		err = proxy(backend, *name, *listen)
	default:
		err = fmt.Errorf("unknown command %q", *command)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func proxy(backend service.Backend, name, listenAddress string) error {
	port, err := servicePort(backend, name)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddress, err)
	}
	defer listener.Close()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		_ = listener.Close()
	}()

	fmt.Fprintf(os.Stderr, "proxying %s to runtime service %s:%d\n", listener.Addr(), name, port)
	for {
		client, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept proxy connection: %w", err)
		}
		go proxyConnection(backend, name, port, client)
	}
}

func servicePort(backend service.Backend, name string) (int, error) {
	services, err := backend.List()
	if err != nil {
		return 0, err
	}
	for _, candidate := range services {
		if candidate.Name == name {
			if candidate.State != service.ServiceStateActive {
				return 0, fmt.Errorf("runtime service %q is not running", name)
			}
			return candidate.Options.ServicePort, nil
		}
	}
	return 0, fmt.Errorf("runtime service %q is not created", name)
}

func proxyConnection(backend service.Backend, name string, port int, client net.Conn) {
	defer client.Close()

	workload, err := backend.DialTCP(name, port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy connection failed: %v\n", err)
		return
	}
	defer workload.Close()

	var once sync.Once
	closeBoth := func() {
		_ = client.Close()
		_ = workload.Close()
	}
	copyStream := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		once.Do(closeBoth)
	}
	go copyStream(workload, client)
	copyStream(client, workload)
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}
