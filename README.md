# Runtime Capability Detection and Best-Effort Isolation

This project provides a standalone runtime library for executing approved,
digest-pinned OCI workloads. The runtime applies every isolation mechanism
available on the host. When OCI isolation cannot be established, an explicit
trusted-workload policy can use the built-in direct executor instead. A system
is unavailable only when neither execution path can safely launch a workload.

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

Only TCP is supported. Missing resource values receive bounded defaults;
invalid or excessive values reject the artifact. CPU, memory, and PID limits
are enforced when the host provides a writable delegated cgroup v2 tree.

The runtime appends two reserved variables to the launched process environment:

- `MYSTERIUM_SERVICE_BIND_ADDRESS`: `127.0.0.1` for a workload with a private
  network namespace, or the service's runtime-assigned address from the managed
  `127.64.0.0/10` host-loopback pool otherwise.
- `MYSTERIUM_SERVICE_PORT`: the manifest's `service.internal_port` value.

Workloads must listen on that exact address and port. An OCI image that declares
either reserved variable is rejected; callers and manifests cannot provide the
assigned address. Host-loopback assignment allows cooperative host-network
workloads to use the same internal port, but it is not network isolation: a
hostile workload may still bind a wildcard address or reach other host services.
Arbitrary untrusted workloads therefore still require a private network
namespace.

## Runtime levels

The runtime reports a scheduler-facing level together with the exact isolation
features selected for new workloads:

1. `unavailable`: Neither the OCI executor nor the built-in direct executor can
   launch a workload. No workload can be spawned.
2. `unisolated`: The built-in `unisolated-v1` direct executor can launch
   trusted workloads, but an OCI isolation boundary is unavailable.
3. `limited`: Workloads can be spawned with a versioned `best-effort-v1`
   profile, but one or more full isolation guarantees are absent.
4. `full`: Workloads receive every guarantee in the versioned `full-v1`
   profile.

### Current isolation profiles

All runnable profiles jail the process in the extracted image rootfs, run it as
the image's numeric non-root UID/GID, and start it with an empty Linux
capability set. The remaining guarantees differ as follows:

| Guarantee | `unisolated-v1` | `best-effort-v1` (`limited`) | `full-v1` |
| --- | --- | --- | --- |
| Execution engine | Built-in direct executor | `runc` | `runc` |
| Private mount and UTS namespaces | No | Yes | Yes |
| Rootfs jail transition | `chroot` | `pivot_root`, or mount-move plus `chroot` with seccomp | `pivot_root` |
| `no_new_privileges` | When available | Required | Required |
| Workload process-tree control | No isolation from the host process tree | Required through a PID namespace, cgroups, or both | PID namespace and cgroups |
| User namespace and UID/GID mappings | No | When available | Required |
| Private network namespace | No | When available | Required |
| Private IPC namespace | No | When available | Required |
| Cgroup v2 CPU, memory, and PID limits | No | When available | Required |
| Seccomp syscall filtering | No | When available | Required |
| Private session keyring | No | With seccomp unavailable; otherwise keyring syscalls are blocked | Required |
| Read-only rootfs | No | When available | Required |

Consequently, a current `limited` profile always has mount isolation,
`no_new_privileges`, and a way to control the complete workload process tree.
Compared with `full`, it may be missing a user namespace, PID namespace,
network namespace, IPC namespace, cgroup resource isolation, seccomp, or a
read-only rootfs. When seccomp is enabled for a limited workload, runc uses its
mount-move plus `chroot` fallback and skips creating a private session keyring
so that restrictive outer seccomp policies cannot prevent startup. The rootfs
remains inside the workload's private mount namespace, and the workload seccomp
policy denies `add_key`, `keyctl`, and `request_key`. PID namespaces and cgroups
cannot both be missing: without at least one of them, the runtime falls back to
`unisolated` (when explicitly authorized) or becomes unavailable. A limited
profile enables each of these additional mechanisms that the host can actually
support, so `limited` is not one fixed set of guarantees.

A private network namespace is selected only when the runtime has both
`CAP_NET_ADMIN` to configure loopback and `CAP_SYS_PTRACE` to open the created
process's `/proc/<pid>/ns/net` handle, and a startup probe confirms that outer
security policy permits `setns`. Without these permissions, a limited workload
shares the runtime's network namespace; full isolation is unavailable.

**A private network namespace means loopback only.** The runtime configures `lo`
and nothing else: no veth pair, no bridge, no NAT. A workload in a private
network namespace has no outbound connectivity and is reachable only through
`Backend.DialTCP`. A workload that instead shares the runtime's network
namespace has whatever access the runtime process has, including egress.

This is the one axis on which the profiles differ in capability rather than in
isolation strength, so it is not a difference a workload can ignore: an image
that reaches the network at runtime will work on a host that selects a shared
network namespace and fail on a host that selects a private one. Workloads
intended for arbitrary hosts must not require egress.

The selected profile and its exact feature vector are persisted with each
installed workload and returned by `list`; a workload is never silently
retried with weaker isolation at start. Runtime status also reports
`missing_for_full`, which names the guarantees preventing the current host from
selecting `full-v1`.

The `unisolated-v1` path does not use `runc`. It starts the image process
directly after entering the extracted rootfs with `chroot`, selecting the
image's numeric non-root UID/GID, clearing supplementary groups and Linux
capabilities, and applying `no_new_privileges` when available. It shares the
host's mount, PID, network, and IPC namespaces, has no cgroup resource limits,
seccomp profile, or read-only rootfs, and is not a security boundary. It is
therefore restricted to digest-pinned workloads that the caller explicitly
marks as safe. Direct workloads must remain in the foreground; only one direct
workload may be active at a time.

Creation requires at least `limited` by default. To authorize a trusted
workload on an `unisolated` device, the caller must explicitly set
`minimum_runtime_level` to `unisolated`. This policy is persisted and checked
again at start. Setting it to `limited` or `full` prevents silent downgrade.

The runtime level is a summary for scheduling. Callers should retain the exact
feature vector because two `limited` devices may provide different guarantees.

---

## 1. Architecture

The runtime is two packages:

```
runtime/
├── capabilities/    # Probes host environment and reports kernel feature support
└── service/         # Workload lifecycle: profile selection, bundle preparation, execution
```

`capabilities` answers "what can this host do?" and has no knowledge of
workloads. `service` turns that answer into a concrete isolation profile,
prepares the OCI bundle, and executes it.

Within `service`, isolation is not applied by hand. `assessRuntime` selects the
profile, `buildOCISpec` encodes every namespace, cgroup, seccomp, capability,
and mount decision into a single generated `config.json`, and `runc` enforces
it. The one exception is the `unisolated-v1` path, where the built-in direct
executor applies its much smaller set of protections itself, because no OCI
runtime is involved.

That means there is exactly one place to change an isolation mechanism for
OCI-executed workloads: the generated spec in `buildOCISpec`, plus the feature
vector that decides what goes into it. Adding Landlock or switching to `crun`
is a change to `service`, not a new subsystem.

## 2. Library and CLI

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
./runtime-cli -command status
./runtime-cli -command capabilities
```

Explicit trusted direct-execution opt-in:

```bash
./runtime-cli -runtime-dir /tmp/myst-runtime \
  -command create \
  -name runtime.trusted \
  -oci-artifact registry.example/trusted-workload@sha256:<digest> \
  -minimum-runtime-level unisolated
```

`runc` is optional for the `unisolated` profile and remains the execution
engine for `limited` and `full`. In the current Linux implementation, the
direct path and rootfs preparation require effective `CHOWN`, `DAC_OVERRIDE`,
`FOWNER`, `KILL`, `SETGID`, `SETUID`, and `SYS_CHROOT` capabilities; they do not
require `SYS_ADMIN`, `NET_ADMIN`, or `MKNOD`.

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
The capability list provides the operational privileges used by the full
profile; the outer Docker seccomp profile is disabled so `runc` can install the
stricter workload seccomp profile from the generated OCI spec.

```bash
docker run --rm --name mysterium-runtime-demo \
  --cgroupns=host \
  --mount type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup \
  --cap-drop=ALL \
  --cap-add=CHOWN \
  --cap-add=DAC_OVERRIDE \
  --cap-add=FOWNER \
  --cap-add=KILL \
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

## 3. Capability Detection Strategy

The `capabilities` package dynamically inspects the execution environment at startup without relying on heuristics such as checking for `.dockerenv`, parsing `/proc/1/cgroup`, or assuming privileges based on containerization. Instead, it probes actual kernel features:

- **Cgroup v2 & Writable Hierarchy**: Probes `/sys/fs/cgroup/cgroup.controllers` and attempts creating a temporary child cgroup directory to verify if child cgroups and `cgroup.procs` can be created by the current process.
- **Namespaces**: Validates `/proc/self/ns/<type>` and namespace sysctls, then starts short-lived child processes which actually clone each requested namespace. The user-namespace probe clones the complete workload namespace set and mounts a fresh procfs; subordinate UID/GID mappings are verified by repeating that execution probe with the configured `/etc/subuid` and `/etc/subgid` ranges.
- **Seccomp**: Invokes `prctl(PR_GET_SECCOMP)` directly to test kernel filtering support and validates `/proc/self/status`.
- **NoNewPrivileges**: Invokes `prctl(PR_GET_NO_NEW_PRIVS)` to verify support for `no_new_privs`.

### Error and Status Reporting
Detection distinguishes between three distinct states via `CapabilityStatus`:
1. `supported`: Available and permitted by kernel and host configuration.
2. `unsupported`: Kernel or OS does not support the feature (or running on non-Linux systems).
3. `unavailable_permissions`: Supported by the kernel but denied due to insufficient permissions (e.g., unprivileged container without `CAP_SYS_ADMIN` or disabled unprivileged user namespaces).

The detector provides both a simplified boolean API (`RuntimeCapabilities`) for decision-making and a detailed structured report (`DetailedCapabilities`) for debugging and telemetry.

---

## 4. Cgroup Resource Isolation

Resource limits are not applied by the runtime directly. The manifest's
`resources` block is validated into a `ResourceLimits` value, encoded into the
generated OCI spec as `linux.resources` under a `cgroupsPath` beneath the
runtime's own delegated cgroup, and enforced by `runc`.

When a writable delegated cgroup v2 tree is available, the limits apply to the
entire workload process tree: `cpu.max` controls CPU bandwidth, `memory.max`
caps memory usage, and `pids.max` limits the number of processes. Without it,
the spec omits both `cgroupsPath` and `linux.resources`, `runc` runs in its
rootless cgroup mode, trusted workloads may still run under the limited profile,
and the runtime reports that cgroup resource isolation is absent through
`IsolationFeatures.Cgroups` and `missing_for_full`.

Note that `disk` is not a persistent-storage limit. It sizes the workload's
`/tmp` tmpfs, and tmpfs pages are charged to the workload's memory cgroup, so a
workload that fills `/tmp` consumes its `memory` budget and will be OOM-killed
rather than receiving a write error.

---

## 5. Future Extension Points

None of the following is implemented. Each is a change to `service`, and each
would need a new `IsolationFeatures` entry so that the guarantee is reported and
re-checked at start rather than silently assumed:

1. **OCI Runtime Selection (runc vs. crun)**:
   `newRuncBackend` hardcodes `runc.DefaultCommand`. It could probe for `crun`
   or `youki` and select a lighter runtime when available.
2. **Landlock File Sandboxing** (`Linux 5.13+`):
   Would restrict filesystem access for workloads that cannot get a mount
   namespace, which is the main gap in the `unisolated-v1` path.
3. **Idmapped Mounts** (`Linux 5.12+`):
   Would allow user-namespace UID/GID shifting without the recursive `chown`
   that `extractImageRootFS` performs today, cutting bundle preparation cost for
   large images.
4. **Outbound Networking for Isolated Workloads**:
   A workload with a private network namespace currently has loopback only. A
   veth pair, slirp4netns/pasta, or a WireGuard-backed interface would give it
   egress without giving it the host's network namespace, which is the only
   alternative the runtime offers today.
5. **Persistent Workload Storage**:
   There is no durable per-workload volume; `/tmp` is memory-backed tmpfs and
   the rootfs is read-only under `full-v1`.
