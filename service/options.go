/*
 * Copyright (C) 2026 The "MysteriumNetwork/node" Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package service

import (
	"bytes"
	"encoding/json"
)

// CreateOptions is the only caller-controlled runtime definition. Everything
// executable is supplied by the digest-pinned artifact.
type CreateOptions struct {
	Name                string       `json:"name"`
	OCIArtifact         string       `json:"oci_artifact"`
	MinimumRuntimeLevel RuntimeLevel `json:"minimum_runtime_level,omitempty"`
}

// ProcessDefinition is normalized from the OCI image config without passing
// through a shell.
type ProcessDefinition struct {
	Args []string `json:"args"`
	Env  []string `json:"env,omitempty"`
	Cwd  string   `json:"cwd"`
	UID  uint32   `json:"uid"`
	GID  uint32   `json:"gid"`
}

// Options is an immutable, validated workload definition.
type Options struct {
	Name                string            `json:"name"`
	OCIArtifact         string            `json:"oci_artifact"`
	ServicePort         int               `json:"service_port"`
	ServiceBindAddress  string            `json:"service_bind_address"`
	Process             ProcessDefinition `json:"process"`
	ResourceLimits      ResourceLimits    `json:"resource_limits"`
	Isolation           IsolationProfile  `json:"isolation"`
	MinimumRuntimeLevel RuntimeLevel      `json:"minimum_runtime_level"`
}

type ResourceLimits struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
	Pids   uint32 `json:"pids"`
}

type Manifest struct {
	SchemaVersion int `json:"schema_version"`
	Service       struct {
		Protocol     string `json:"protocol"`
		InternalPort int    `json:"internal_port"`
	} `json:"service"`
	Resources ResourceLimits `json:"resources"`
}

func ParseJSONOptions(request *json.RawMessage) (CreateOptions, error) {
	var options CreateOptions
	if request == nil {
		return options, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(*request))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&options)
	return options, err
}
