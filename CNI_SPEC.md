# CNI Specification v1.1.0 — Agent Reference

> Condensed from https://github.com/containernetworking/cni/blob/main/SPEC.md
> Current spec version: **1.1.0**

## Key Terms

- **container**: network isolation domain (e.g. network namespace)
- **network**: group of uniquely addressable endpoints
- **runtime**: program that executes CNI plugins
- **plugin**: program that applies a network configuration

---

## Section 1: Network Configuration Format

A network configuration is a JSON object with these keys:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `cniVersion` | string | yes | Semver of CNI spec (e.g. `"1.1.0"`) |
| `cniVersions` | string[] | no | All CNI versions this config supports |
| `name` | string | yes | Unique network name. Must start with alphanumeric; may contain alphanumeric, `_`, `.`, `-` |
| `disableCheck` | boolean | no | If `true`, runtime MUST NOT call `CHECK` |
| `disableGC` | boolean | no | If `true`, runtime MUST NOT call `GC` |
| `loadOnlyInlinedPlugins` | boolean | no | If `true`, ignore plugins from external sources |
| `plugins` | object[] | no | List of plugin configuration objects |

### Plugin Configuration Object

**Required:**
- `type` (string): CNI plugin binary name. No path separators (`/` or `\`).

**Optional (protocol):**
- `capabilities` (object): declares supported capability keys (see runtimeConfig derivation)

**Reserved (set by runtime, not config):**
- `runtimeConfig`
- `args`
- any key starting with `cni.dev/`

**Well-known optional:**
- `ipMasq` (boolean): set up IP masquerade on host
- `ipam.type` (string): IPAM plugin binary name
- `dns.nameservers` (string[]): DNS nameserver IPs
- `dns.domain` (string): local domain for short lookups
- `dns.search` (string[]): search domains
- `dns.options` (string[]): resolver options

Plugins may define additional fields; runtime MUST pass them through unchanged.

### Version Selection

Runtime MUST select the highest supported version from `cniVersion`/`cniVersions`.
Spec follows SemVer — config format is backwards/forwards compatible within major versions.

---

## Section 2: Execution Protocol

Plugins are binaries invoked by the runtime. Protocol:
- Parameters → OS environment variables
- Configuration → stdin (JSON)
- Success result → stdout (JSON)
- Errors → stderr + non-zero exit code

Runtime MUST execute plugins in the root network namespace.

### Environment Variables

| Variable | Required for | Description |
|----------|-------------|-------------|
| `CNI_COMMAND` | all | `ADD`, `DEL`, `CHECK`, `GC`, `STATUS`, or `VERSION` |
| `CNI_CONTAINERID` | ADD, DEL, CHECK | Unique container ID. Alphanumeric + `_`, `.`, `-` |
| `CNI_NETNS` | ADD, CHECK | Path to network namespace (e.g. `/run/netns/foo`) |
| `CNI_IFNAME` | ADD, DEL, CHECK | Interface name to create inside container |
| `CNI_ARGS` | optional | `KEY=VAL;KEY2=VAL2` extra arguments |
| `CNI_PATH` | GC, optional others | `:` separated paths to search for plugin binaries |

### Operations

#### `ADD` — Add container to network

Plugin MUST:
- Create interface `CNI_IFNAME` in `CNI_NETNS`, OR adjust an existing interface
- Output a [Success result](#add-success) on stdout
- If given `prevResult`, either pass it through or modify it and output the updated result
- Return an error if the interface already exists in the container

Runtime SHOULD NOT call `ADD` twice for the same `(CNI_CONTAINERID, CNI_IFNAME)` without an intervening `DEL`.

Required env: `CNI_COMMAND`, `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME`
Optional env: `CNI_ARGS`, `CNI_PATH`

#### `DEL` — Remove container from network

Plugin MUST:
- Delete interface `CNI_IFNAME` from `CNI_NETNS`, OR undo ADD modifications
- Accept multiple `DEL` calls for the same `(CNI_CONTAINERID, CNI_IFNAME)` and return success if already gone
- Complete the DEL to the fullest extent possible (best-effort, always return success)

`prevResult` MUST be supplied (the final ADD result). Plugin should still return success if `prevResult` is empty.

Required env: `CNI_COMMAND`, `CNI_CONTAINERID`, `CNI_IFNAME`
Optional env: `CNI_NETNS`, `CNI_ARGS`, `CNI_PATH`

#### `CHECK` — Verify container networking

Plugin MUST:
- Consult `prevResult` to determine expected interfaces and addresses
- Return error if any resource it created is listed in `prevResult` but missing or invalid
- Return error if the container is generally unreachable
- Allow for asynchronous convergence delay
- Call `CHECK` on any delegated plugins

Plugin MUST allow for later chained plugins to have modified resources (e.g. routes).

Runtime MUST:
- Not call `CHECK` for a container that hasn't been `ADD`ed or has been `DEL`eted
- Not call `CHECK` if `disableCheck` is `true`
- Include `prevResult` (final ADD result) in the configuration

Required env: `CNI_COMMAND`, `CNI_CONTAINERID`, `CNI_NETNS`, `CNI_IFNAME` (same as ADD)
Optional env: `CNI_ARGS`, `CNI_PATH`

#### `STATUS` — Check plugin readiness

Plugin MUST exit 0 if ready to service ADD requests, non-zero otherwise.

Error codes for STATUS:
- `50`: plugin not available (cannot service ADD)
- `51`: plugin not available, existing containers may have limited connectivity

Plugin MUST NOT rely on STATUS being called. Other CNI operations MUST still be handled even if STATUS returns error.

Required env: none
Optional env: `CNI_PATH`

#### `VERSION` — Probe supported versions

Input: JSON with `cniVersion` key.
Output: [VERSION Success result](#version-success).

Required env: `CNI_COMMAND`

#### `GC` — Garbage collect stale resources

Input includes `cni.dev/valid-attachments` (array of `{containerID, ifname}` still valid).
Plugin SHOULD remove resources for any attachments NOT in that list.
Plugin MUST forward GC to any delegated plugins.
On error, plugin SHOULD continue removing as many resources as possible and report all errors.
Runtime MUST NOT use GC as a substitute for DEL.

Required env: `CNI_COMMAND`, `CNI_PATH`
Output: nothing on success, [Error result](#error) on failure.

### Error Codes

| Code | Description |
|------|-------------|
| 1 | Incompatible CNI version |
| 2 | Unsupported field in network config (msg must include key/value) |
| 3 | Container unknown or does not exist (no cleanup needed) |
| 4 | Invalid environment variables (msg must include variable names) |
| 5 | I/O failure (e.g. failed to read stdin) |
| 6 | Failed to decode content (e.g. unmarshal failure) |
| 7 | Invalid network config |
| 11 | Try again later (transient condition) |
| 50 | Plugin not available |
| 51 | Plugin not available, containers may have limited connectivity |
| 100+ | Plugin-specific errors |

---

## Section 3: Execution of Network Configurations

### Lifecycle Rules

- Runtime MUST create a network namespace before invoking any plugins
- Runtime MUST NOT invoke parallel operations for the same container
- Runtime MAY invoke parallel operations for different containers
- GC is exclusive: no ADD/DEL may be in progress; GC must complete before new ADD/DEL
- Plugins MUST handle concurrent execution across different containers (use locking on shared resources)
- Runtime MUST ensure ADD is eventually followed by DEL (even if ADD failed)
- Multiple DELs are allowed
- Network config SHOULD NOT change between ADD and DELETE, or between attachments

### Attachment Parameters (per-invocation)

- `CNI_CONTAINERID`: unique container ID
- `CNI_NETNS`: network namespace path
- `CNI_IFNAME`: interface name
- `CNI_ARGS`: `KEY=VAL;...` generic arguments
- Capability arguments: key-value pairs, keys/values defined by convention
- `CNI_PATH`: plugin search paths

### Adding an Attachment

For each plugin in `plugins` (in order):
1. Look up binary by `type`; error if not found
2. Derive request config: no `prevResult` for first plugin; previous plugin's result for subsequent
3. Execute with `CNI_COMMAND=ADD`
4. On error, halt and return error

Runtime MUST persistently store the final plugin's result (needed for CHECK and DEL).

### Deleting an Attachment

For each plugin in `plugins` (**reverse order**):
1. Look up binary by `type`; error if not found
2. Derive request config with `prevResult` = final ADD result
3. Execute with `CNI_COMMAND=DEL`
4. On error, halt and return error

### Checking an Attachment

Same as ADD order, but:
- `prevResult` is always the final ADD result
- If `disableCheck` is set, return success immediately

### Garbage-Collecting a Network

For each plugin in `plugins` (in order):
1. Look up binary by `type`; error if not found
2. Derive request config
3. Execute with `CNI_COMMAND=GC`
4. On error, **continue** (do not halt); collect all errors and return them

### Deriving Request Configuration

The single-plugin request config is derived from the network config with these changes:

**Always set:**
- `cniVersion`: protocol version selected by runtime (e.g. `"1.1.0"`)
- `name`: from network config `name`

**For ADD/DEL/CHECK:**
- `runtimeConfig`: union of capabilities supported by the plugin AND provided by the runtime
- `prevResult`: result from previous plugin (not set for first ADD)
- `capabilities`: MUST NOT be set (removed)

**For GC:**
- `cni.dev/valid-attachments`: array of `{containerID, ifname}` objects

All other non-`cni.dev/`-prefixed fields pass through unchanged.

#### Deriving `runtimeConfig`

Plugin declares capabilities in config:
```json
{ "type": "myPlugin", "capabilities": { "portMappings": true } }
```

Runtime provides capability arguments. The intersection (plugin declares AND runtime provides) is placed in `runtimeConfig`:
```json
{ "type": "myPlugin", "runtimeConfig": { "portMappings": [{ "hostPort": 8080, "containerPort": 80, "protocol": "tcp" }] } }
```

---

## Section 4: Plugin Delegation

Plugins may delegate functionality to other plugins (e.g. IPAM).

### Delegated Plugin Protocol

- Binary is found via `CNI_PATH`
- Receives the **complete** network configuration (not just a subsection)
- Receives the same environment variables as the calling plugin
- Delegated plugin's stderr MUST be forwarded to calling plugin's stderr
- Success: zero exit code + Success result on stdout

### Delegation Rules

- On `CHECK`, `DEL`, or `GC`: plugin MUST execute delegated plugins; propagate errors
- On `ADD`: if delegated plugin fails, calling plugin MUST execute `DEL` before returning failure

---

## Section 5: Result Types

### ADD Success

Output JSON on stdout:

```json
{
  "cniVersion": "1.1.0",
  "interfaces": [
    {
      "name": "eth0",
      "mac": "00:11:22:33:44:55",
      "mtu": 1500,
      "sandbox": "/var/run/netns/blue",
      "socketPath": "/path/to/socket",
      "pciID": "0000:00:1f.6"
    }
  ],
  "ips": [
    {
      "address": "192.168.1.5/24",
      "gateway": "192.168.1.1",
      "interface": 0
    }
  ],
  "routes": [
    {
      "dst": "0.0.0.0/0",
      "gw": "192.168.1.1",
      "mtu": 1500,
      "advmss": 1460,
      "priority": 100,
      "table": 254,
      "scope": 0
    }
  ],
  "dns": {
    "nameservers": ["8.8.8.8"],
    "domain": "example.com",
    "search": ["example.com"],
    "options": []
  }
}
```

Field details:
- `interfaces[].sandbox`: empty = host interface; set to `CNI_NETNS` value for container interfaces
- `ips[].interface`: index into `interfaces` array
- `routes[].scope`: 0 = global, 253 = link, 254 = host

If given `prevResult`, plugin MUST output it with any modifications applied. If no changes, output equivalent to `prevResult`.

#### Delegated (IPAM) Plugin Success

Omits `interfaces` array and `ips[].interface` field.

### VERSION Success

```json
{
  "cniVersion": "1.1.0",
  "supportedVersions": ["0.3.1", "0.4.0", "1.0.0", "1.1.0"]
}
```

### Error

```json
{
  "cniVersion": "1.1.0",
  "code": 7,
  "msg": "Invalid Configuration",
  "details": "Network 192.168.0.0/31 too small to allocate from."
}
```

Plugin MUST exit non-zero and output this on stderr (unstructured logs also allowed on stderr).

---

## Quick Reference: Operation Summary

| Operation | prevResult in | prevResult out | Output | Idempotent |
|-----------|--------------|----------------|--------|------------|
| ADD | none (first) or previous plugin result | yes, pass-through or modified | Success result | no (error if iface exists) |
| DEL | final ADD result | no | none | yes (MUST accept multiple) |
| CHECK | final ADD result | no | none (success = exit 0) | yes |
| STATUS | — | no | none or Error | yes |
| VERSION | — | no | VERSION result | yes |
| GC | — | no | none or Error | yes |
