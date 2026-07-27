package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mysteriumnetwork/runtime/capabilities"
	"github.com/mysteriumnetwork/runtime/service"
)

type capabilitiesOutput struct {
	Capabilities capabilities.RuntimeCapabilities  `json:"capabilities"`
	Detailed     capabilities.DetailedCapabilities `json:"detailed"`
}

func main() {
	runtimeDir := flag.String("runtime-dir", "/tmp/myst-runtime", "runtime data directory")
	command := flag.String("command", "", "command: list|capabilities|create|delete|start|stop")
	name := flag.String("name", "", "service name")
	artifact := flag.String("oci-artifact", "", "OCI artifact reference")
	flag.Parse()

	if strings.TrimSpace(*command) == "" {
		fmt.Fprintln(os.Stderr, "command is required")
		os.Exit(1)
	}

	backend := service.NewBackend(*runtimeDir)

	options := service.CreateOptions{
		Name:        *name,
		OCIArtifact: *artifact,
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
		printJSON(capabilitiesOutput{Capabilities: caps, Detailed: detailed})
	case "create":
		err = backend.Create(options)
	case "delete":
		err = backend.Delete(*name)
	case "start":
		err = backend.Start(*name)
	case "stop":
		err = backend.Stop(*name)
	default:
		err = fmt.Errorf("unknown command %q", *command)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}
