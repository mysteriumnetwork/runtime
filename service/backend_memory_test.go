package service

import "testing"

func TestMemoryBackendStartRequiresCreatedDefinition(t *testing.T) {
	backend := NewMemoryBackend()
	if err := backend.Start("runtime.missing"); err == nil {
		t.Fatal("expected start of an unknown definition to fail")
	}
}

func TestMemoryBackendStartCannotOverrideDefinition(t *testing.T) {
	backend := NewMemoryBackend()
	input := CreateOptions{Name: "runtime.test", OCIArtifact: "example.invalid/test@sha256:abc"}
	if err := backend.Create(input); err != nil {
		t.Fatal(err)
	}
	if err := backend.Start(input.Name); err != nil {
		t.Fatal(err)
	}
	services, err := backend.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].Options.OCIArtifact != input.OCIArtifact {
		t.Fatalf("definition changed during start: %#v", services)
	}
}
