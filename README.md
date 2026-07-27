# Runtime Capability Detection and Resource Isolation

This project provides a standalone runtime library for executing approved,
digest-pinned OCI workloads. Runtime execution is fail-closed: when the host
cannot provide every required isolation boundary, the runtime reports itself
unavailable and the node continues without activating runtime services.

## Workload contract

`create` accepts only a service name and an OCI artifact reference containing a
digest (`registry/repository@sha256:...`). `start` accepts only the installed
service name. Start-time command, environment, rootfs, port, and resource
overrides are intentionally unsupported.

Process arguments, environment, working directory, and numeric non-root user
come from the standard OCI image config (`Entrypoint`, `Cmd`, `Env`,
`WorkingDir`, and `User`). Argument arrays are preserved exactly and are never
parsed through a shell.

The image root must contain `/mysterium-runtime.json`:

```json
{
  "schema_version": 1,
  "service": {
    "protocol": "tcp",
    "internal_port": 3000
  },
  "resources": {
    "cpu": "1",
    "memory": "512MiB",
    "disk": "512MiB",
    "pids": 128
  }
}
```

Only TCP is supported. Missing resource values receive mandatory bounded
defaults; invalid or excessive values reject the artifact.

---

## 1. Architecture

The runtime architecture decomposes container and workload execution into six independent packages:

```
runtime/
├── capabilities/    # Probes host environment and reports kernel feature support
├── resources/       # Cgroup v2 resource limiting
├── namespaces/      # Linux namespace topology abstractions (user, mnt, pid, net, ipc, uts)
├── filesystem/      # Rootfs preparation, read-only rootfs enforcement, and bind-mounts
├── network/         # Workload networking topology, bridge setup, and port forwarding
└── security/        # Seccomp profiles, capability dropping, and no_new_privs rules
```

This clean separation ensures that changes in isolation mechanisms (e.g., adding Landlock or switching from runc to crun) do not require changes to service managers or workload execution code.

## 5. Library and CLI

This module also provides:

- `service`: core runtime library API used by node
- `cmd/runtime-cli`: local CLI for testing and development

### Build locally

```bash
go build ./cmd/runtime-cli
```

### Example CLI usage

```bash
./runtime-cli -runtime-dir /tmp/myst-runtime -command create -name runtime.test1 -oci-artifact registry.example/workload@sha256:<digest>
./runtime-cli -command start -name runtime.test1
./runtime-cli -command list
```

### Docker demo

The root [`Dockerfile`](Dockerfile) builds an Alpine image containing
`runtime-cli`, `runc`, and `curl`. The demo workload in
[`examples/nc-workload`](examples/nc-workload) uses BusyBox `nc` and `cat` to
return a small HTTP response.

The runtime accepts only registry images referenced by digest, so first publish
the workload to a registry the runtime container can reach:

```bash
export WORKLOAD_IMAGE=registry.example/mysterium/nc-workload:demo

docker build -t "$WORKLOAD_IMAGE" examples/nc-workload
docker push "$WORKLOAD_IMAGE"
export OCI_ARTIFACT="$(docker image inspect "$WORKLOAD_IMAGE" \
  --format '{{index .RepoDigests 0}}')"

case "$OCI_ARTIFACT" in
  *@sha256:*) ;;
  *) echo "the pushed workload did not resolve to a digest" >&2; exit 1 ;;
esac
```

Build the runtime image:

```bash
docker build -t mysterium-runtime:dev .
```

Run the end-to-end demo on a native Linux Docker host. Docker Desktop is not a
supported host for this nested runtime because its VM blocks the subordinate
user namespace from mounting the workload procfs. The cgroup namespace and cgroup
filesystem options let the demo wrapper delegate `cpu`, `memory`, and `pids`
from the container cgroup to sibling workload cgroups managed by nested `runc`.
The capability list is the exact set currently required by the runtime's
availability check; the outer Docker seccomp profile is disabled so `runc` can
install the stricter workload seccomp profile from the generated OCI spec.

```bash
docker run --rm --name mysterium-runtime-demo \
  --cgroupns=host \
  --mount type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup \
  --cap-drop=ALL \
  --cap-add=CHOWN \
  --cap-add=DAC_OVERRIDE \
  --cap-add=FOWNER \
  --cap-add=SETGID \
  --cap-add=SETUID \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_CHROOT \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --cap-add=MKNOD \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -e OCI_ARTIFACT="$OCI_ARTIFACT" \
  -p 127.0.0.1:3000:3000 \
  --entrypoint /usr/local/bin/runtime-demo \
  mysterium-runtime:dev
```

In a second terminal:

```bash
curl --fail-with-body http://127.0.0.1:3000/
```

Expected response:

```text
hello from the isolated runc workload
```

The `proxy` command used by the demo is necessary because the workload listens
only on loopback inside its isolated network namespace. It looks up the
manifest-defined service port and bridges a local listener through
`Backend.DialTCP`; it does not add a port override to the workload contract.

---

## 2. Capability Detection Strategy

The `capabilities` package dynamically inspects the execution environment at startup without relying on heuristics such as checking for `.dockerenv`, parsing `/proc/1/cgroup`, or assuming privileges based on containerization. Instead, it probes actual kernel features:

- **Cgroup v2 & Writable Hierarchy**: Probes `/sys/fs/cgroup/cgroup.controllers` and attempts creating a temporary child cgroup directory to verify if child cgroups and `cgroup.procs` can be created by the current process.
- **Namespaces**: Probes `/proc/self/ns/<type>` and validates sysctl limits (e.g., `/proc/sys/user/max_user_namespaces` and `/proc/sys/kernel/unprivileged_userns_clone`) to ensure unprivileged cloning is permitted.
- **Seccomp**: Invokes `prctl(PR_GET_SECCOMP)` directly to test kernel filtering support and validates `/proc/self/status`.
- **NoNewPrivileges**: Invokes `prctl(PR_GET_NO_NEW_PRIVS)` to verify support for `no_new_privs`.

### Error and Status Reporting
Detection distinguishes between three distinct states via `CapabilityStatus`:
1. `supported`: Available and permitted by kernel and host configuration.
2. `unsupported`: Kernel or OS does not support the feature (or running on non-Linux systems).
3. `unavailable_permissions`: Supported by the kernel but denied due to insufficient permissions (e.g., unprivileged container without `CAP_SYS_ADMIN` or disabled unprivileged user namespaces).

The detector provides both a simplified boolean API (`RuntimeCapabilities`) for decision-making and a detailed structured report (`DetailedCapabilities`) for debugging and telemetry.

---

## 3. Cgroup Resource Isolation

The `resources` package defines a generic `ResourceLimiter` interface:
```go
type ResourceLimiter interface {
    Create(id string, limits ResourceLimits) error
    Attach(pid int) error
    Destroy(id string) error
}
```

Runtime workloads require a writable delegated cgroup v2 tree. Resource limits
apply to the entire workload process tree: `cpu.max` controls CPU bandwidth,
`memory.max` caps memory usage, and `pids.max` limits the number of processes.
If the required cgroup hierarchy is unavailable, resource isolation fails
closed.

---

## 4. Future Extension Points

The architecture provides clear extension points for emerging Linux security and isolation technologies:

1. **OCI Runtime Selection (runc vs. crun)**:
   The `service` backend can be extended to detect installed OCI runtime binaries (`crun`, `runc`, `youki`) and dynamically select lightweight C-based runtimes (`crun`) when available.
2. **Landlock File Sandboxing**:
   The `security` package includes a stub for Landlock (`Linux 5.13+`). Workloads running without root privileges or mount namespaces can use Landlock rules to restrict filesystem access unprivilege-wide.
3. **Idmapped Mounts**:
   The `filesystem` package supports configuring `IdMapped: true`, enabling user namespace uid/gid shifting on bind mounts without recursively `chown`-ing the underlying files (`Linux 5.12+`).
4. **Cgroup Delegation & Rootless Execution**:
   When `UserNamespaces` and cgroup v2 delegation (`cgroup.controllers` delegated to unprivileged users via systemd/logind) are detected, the runtime can launch rootless containers seamlessly without root daemon privileges.
5. **Custom Network Namespace Providers**:
   The `network` package interface permits plugging in external CNI plugins, user-mode TCP/IP stacks (such as slirp4netns or pasta), or WireGuard-backed network interfaces directly into isolated container network namespaces.
