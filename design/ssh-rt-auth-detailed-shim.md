# ssh-rt-auth Detailed Design: Shim

**Project:** ssh-rt-auth  
**Status:** Detailed design v0.1  
**Author:** Kurt Godwin (github.com/kurt-cb)  
**Scope:** Authorization shim — the component between sshd and the CA  

---

## Purpose

The shim is a shared library (or callable module) that sshd invokes after successful
userauth. It is the only ssh-rt-auth component that runs on the server alongside sshd.
Its job is narrow:

1. Receive identity proof and connection context from sshd
2. Check the local cache for a valid authorization cert
3. If cache miss, query the CA over mTLS (with failover)
4. Return the authorization cert (or denial) to sshd
5. sshd enforces the cert's constraints

The shim does not evaluate policy. It does not parse identity blobs beyond what's
needed for cache key computation. It does not interpret the authorization cert's
extensions — that's sshd's job after the shim returns.

---

## Interface: sshd → shim

The shim exposes a single entry point. The exact calling convention depends on the
sshd implementation, but the logical interface is the same across all targets.

### Function signature

```c
/**
 * Called by sshd after successful userauth, before granting access.
 *
 * @param identity_type   "pubkey" or "openssh-cert"
 * @param identity_data   Raw identity blob (public key or cert), wire format
 * @param identity_len    Length of identity_data in bytes
 * @param source_ip       Client source IP as string (e.g., "10.0.1.42")
 * @param source_port     Client source port
 * @param timestamp       Connection time, seconds since epoch (UTC)
 * @param channels        Requested channel types, NULL-terminated array of strings
 *                        (may be NULL if not available)
 * @param out_cert        On success, receives pointer to DER-encoded X.509 cert
 * @param out_cert_len    On success, receives length of cert in bytes
 * @param out_serial      On success, receives cert serial as hex string (for logging)
 *
 * @return  0  authorized (out_cert populated)
 *         -1  denied (connection should be rejected)
 *         -2  error (connection should be rejected, log the failure)
 */
int ssh_rt_auth_authorize(
    const char   *identity_type,
    const uint8_t *identity_data,
    size_t         identity_len,
    const char   *source_ip,
    uint16_t       source_port,
    uint64_t       timestamp,
    const char   **channels,
    uint8_t      **out_cert,
    size_t        *out_cert_len,
    char         **out_serial
);
```

### Return values

| Return | Meaning | sshd action |
|--------|---------|-------------|
| `0` | Authorized. `out_cert` contains the X.509 authorization cert. | Accept the connection. Enforce cert constraints during session. |
| `-1` | Denied. The CA explicitly refused authorization. | Reject the connection. Log denial. |
| `-2` | Error. CA unreachable, config error, internal failure. | Reject the connection. Log error. |

The shim never returns "authorized" without a valid cert. If the CA grants access
but the cert fails local validation (bad signature, expired, unrecognized critical
extension), the shim returns `-2`.

### Memory management

The shim allocates `out_cert` and `out_serial`. sshd frees them after use with
`ssh_rt_auth_free(void *ptr)`. This avoids cross-library allocation issues.

```c
void ssh_rt_auth_free(void *ptr);
```

### Initialization and cleanup

```c
/**
 * Initialize the shim. Called once at sshd startup.
 * Loads config, initializes mTLS context, opens cache.
 *
 * @param config_path  Path to shim config file
 * @return 0 on success, -1 on failure
 */
int ssh_rt_auth_init(const char *config_path);

/**
 * Cleanup. Called at sshd shutdown.
 * Closes mTLS connections, flushes cache, frees resources.
 */
void ssh_rt_auth_cleanup(void);
```

---

## Shim configuration

All ssh-rt-auth configuration lives in the shim's config file. sshd_config has
only one directive:

```
# sshd_config
AuthorizationModule /usr/lib/ssh-rt-auth/libsshrtauth.so
AuthorizationModuleConfig /etc/ssh-rt-auth/config.yaml
```

### Config file format

```yaml
# /etc/ssh-rt-auth/config.yaml

# CA endpoints, tried in order (failover)
ca_endpoints:
  - https://ca1.internal:8443
  - https://ca2.internal:8443

# mTLS client cert and key for this server's identity
mtls_cert: /etc/ssh-rt-auth/server.pem
mtls_key: /etc/ssh-rt-auth/server-key.pem

# Trust root for validating the CA's server cert
ca_trust_root: /etc/ssh-rt-auth/ca-root.pem

# Trust root for validating authorization certs returned by the CA
auth_trust_root: /etc/ssh-rt-auth/auth-signing-root.pem

# Cache configuration
cache:
  dir: /var/cache/ssh-rt-auth
  max_entries: 1000          # LRU eviction after this many entries

# Connection timeouts (seconds)
timeouts:
  connect: 5
  read: 10
  total: 15

# Emergency cert (break-glass, used when all CAs are unreachable)
emergency_cert: /etc/ssh-rt-auth/emergency.pem
emergency_trust_root: /etc/ssh-rt-auth/emergency-root.pem

# Logging
log:
  level: info                # debug, info, warn, error
  file: /var/log/ssh-rt-auth/shim.log
```

### Config validation

The shim validates the config at `ssh_rt_auth_init()` time:

- At least one `ca_endpoints` entry
- `mtls_cert` and `mtls_key` exist and are a valid key pair
- `ca_trust_root` and `auth_trust_root` exist and are parseable X.509 certs
- `cache.dir` exists and is writable
- `emergency_cert`, if specified, is a valid X.509 cert signed by `emergency_trust_root`

If validation fails, `ssh_rt_auth_init()` returns `-1` and sshd should refuse to
start (fail-closed).

---

## Cache

The shim maintains a local cache of authorization certs to avoid querying the CA
on every connection.

### Cache key

The cache key is a tuple of:

```
(identity_fingerprint, source_ip)
```

Where `identity_fingerprint` is the SHA-256 fingerprint of the raw identity blob
(computed by the shim — this is the only parsing the shim does on the identity data).

Including `source_ip` in the cache key ensures that a cached cert with
`sshrtauth-source-bind` is not reused for connections from a different source.
This is conservative — if the CA's policy doesn't source-bind, the cert would be
valid from any IP, but the shim doesn't parse the cert's extensions to determine
this. It's simpler and safer to include `source_ip` unconditionally.

### Cache entry

```
{
  key:          (fingerprint, source_ip)
  cert_der:     raw DER-encoded X.509 cert
  serial:       cert serial as hex string
  not_after:    expiry time (from cert's notAfter)
  created_at:   when this entry was cached
}
```

### Cache lookup

On each `ssh_rt_auth_authorize()` call:

1. Compute the cache key from the identity blob fingerprint and source IP
2. Look up the key in the cache
3. If found and `not_after > now`: cache hit, return the cached cert
4. If found and `not_after <= now`: expired, evict the entry, proceed to CA query
5. If not found: cache miss, proceed to CA query

### Cache storage

The PoC cache is a simple on-disk directory:

```
/var/cache/ssh-rt-auth/
  SHA256_AbCdEf..._10.0.1.42.der    # cert in DER format
  SHA256_AbCdEf..._10.0.1.42.meta   # JSON: serial, not_after, created_at
```

The file naming convention uses the fingerprint and source IP to form the filename.
The `.meta` file holds expiry info so the shim can check TTL without parsing the cert.

Production implementations may use an in-memory cache (hash table) with LRU eviction.
The interface is the same.

### Cache eviction

- **TTL-based:** Entries removed when `not_after` has passed.
- **LRU-based:** When `max_entries` is reached, least-recently-used entry is evicted.
- **Startup cleanup:** On `ssh_rt_auth_init()`, scan the cache directory and remove
  expired entries.

---

## CA communication

### Request construction

When the cache misses, the shim constructs an HTTP POST request to `POST /v1/authorize`:

```json
{
  "identity": {
    "type": "<identity_type from sshd>",
    "data": "<base64-encoded identity_data>"
  },
  "connection": {
    "source_ip": "<source_ip from sshd>",
    "source_port": <source_port from sshd>,
    "timestamp": "<ISO 8601 UTC from timestamp>"
  },
  "requested_channels": ["<channels from sshd, if provided>"]
}
```

The shim base64-encodes the raw identity blob and formats the timestamp as ISO 8601.
No other transformation.

### mTLS connection

The shim establishes an mTLS connection to the CA:

- Client cert: `mtls_cert` and `mtls_key` from config
- Server validation: `ca_trust_root` from config
- TLS 1.3 minimum (TLS 1.2 acceptable for PoC)

The shim may maintain a persistent connection pool to the CA to avoid TLS handshake
overhead on every authorization query. Connection pool management is an implementation
detail.

### Failover

```
for each endpoint in ca_endpoints (in order):
    try:
        connect with timeout (timeouts.connect)
        send request
        read response with timeout (timeouts.read)
        if response is valid:
            return response
    catch connection error, timeout:
        log warning: "CA endpoint {endpoint} unreachable, trying next"
        continue

# All endpoints exhausted
check emergency cert (if configured)
if emergency cert valid:
    return emergency cert
else:
    return error (-2)
```

Failover is simple and sequential. No health checking, no circuit breakers, no
weighted routing. Try them in order, use the first one that responds.

### Response handling

On receiving a response from the CA:

```
if HTTP 200 and status == "granted":
    decode cert from base64
    validate cert signature against auth_trust_root
    validate cert not expired
    validate cert has no unrecognized critical extensions
    if all valid:
        cache the cert
        return 0 (authorized) with cert data
    else:
        log error: "CA returned invalid cert: {reason}"
        return -2 (error)

if HTTP 403 and status == "denied":
    log info: "Authorization denied: {reason} {detail}"
    return -1 (denied)

if HTTP 5xx or status == "error":
    log error: "CA error: {reason} {detail}"
    try next endpoint (failover)

if unexpected response:
    log error: "Unexpected response from CA"
    try next endpoint (failover)
```

The shim validates the authorization cert before caching it. A cert with an invalid
signature, an expired validity window, or an unrecognized critical extension is
rejected even if the CA returned HTTP 200. This is defense in depth — the shim does
not blindly trust the CA's response.

---

## Emergency cert handling

The emergency cert is a long-lived authorization cert held locally on the server,
used only when all CA endpoints are unreachable. It is validated against a separate
trust root (`emergency_trust_root`), not the regular `auth_trust_root`.

```
if all CA endpoints fail:
    if emergency_cert configured:
        load emergency cert from disk
        validate against emergency_trust_root
        check not expired
        check sshrtauth-server-bind matches this server (if present)
        if valid:
            return 0 (authorized) with emergency cert
        else:
            return -2 (error, emergency cert invalid)
    else:
        return -2 (error, no CAs reachable)
```

The emergency cert is not cached. It is re-read from disk and re-validated on every
use. This ensures that if an admin replaces or revokes the emergency cert, the change
takes effect immediately.

---

## Integration with SSH implementations

### OpenSSH

The sshd patch adds a call to `ssh_rt_auth_authorize()` in `auth.c` or `auth2.c`,
after `userauth_finish()` succeeds and before the session is established.

```c
// In the OpenSSH auth path, after userauth succeeds:
if (options.authorization_module != NULL) {
    int rc = ssh_rt_auth_authorize(
        authctxt->identity_type,    // "pubkey" or "openssh-cert"
        authctxt->identity_data,    // raw key/cert blob
        authctxt->identity_len,
        ssh_remote_ipaddr(ssh),     // source IP
        ssh_remote_port(ssh),       // source port
        (uint64_t)time(NULL),       // timestamp
        NULL,                       // channels not known at this point
        &auth_cert, &auth_cert_len, &auth_serial
    );
    if (rc != 0) {
        // deny the connection
        authctxt->success = 0;
        return;
    }
    // store auth_cert for constraint enforcement during session
    authctxt->rt_auth_cert = auth_cert;
    authctxt->rt_auth_cert_len = auth_cert_len;
    authctxt->rt_auth_serial = auth_serial;
}
```

New sshd_config directives:

```
AuthorizationModule /usr/lib/ssh-rt-auth/libsshrtauth.so
AuthorizationModuleConfig /etc/ssh-rt-auth/config.yaml
```

Parsed in `servconf.c`, stored in `ServerOptions`.

### Dropbear

Similar pattern. Dropbear's auth path is in `svr-auth.c`. After `send_msg_userauth_success()`,
call into the shim. Dropbear links against the shim as a shared library.

The shim's C interface is designed to be compatible with Dropbear's simpler codebase.
No OpenSSH-specific types are used in the interface — all parameters are plain C types
(strings, byte arrays, integers).

### Python SSH servers (Paramiko, AsyncSSH)

The shim can be called via ctypes/cffi from Python, or a thin Python wrapper can
reimplement the shim logic natively (HTTP client, mTLS, cache). For the PoC, a
Python-native shim is acceptable since the PoC CA is also Python.

```python
# Python shim interface (equivalent to the C interface)

class SshRtAuth:
    def __init__(self, config_path: str):
        """Load config, initialize mTLS context, open cache."""

    def authorize(
        self,
        identity_type: str,      # "pubkey" or "openssh-cert"
        identity_data: bytes,    # raw key/cert blob
        source_ip: str,
        source_port: int,
        timestamp: int,          # epoch seconds UTC
        channels: list[str] | None = None,
    ) -> tuple[int, bytes | None, str | None]:
        """
        Returns (status, cert_der, serial)
        status: 0 = authorized, -1 = denied, -2 = error
        """

    def cleanup(self):
        """Close connections, flush cache."""
```

---

## Constraint enforcement in sshd

After the shim returns an authorization cert, sshd must enforce the cert's
constraints during the session. This is sshd's responsibility, not the shim's.

### Extensions sshd must enforce

| Extension | Enforcement |
|-----------|-------------|
| `sshrtauth-source-bind` | Reject the connection if the source IP doesn't match. (The shim's cache already accounts for this, but sshd should verify as defense in depth.) |
| `sshrtauth-server-bind` | Reject the connection if the server-bind value doesn't match this server's canonical name (configured locally). |
| `sshrtauth-channel-policy` | On each channel open request, check the channel type against the allowed list. Reject channel types not in the list. |
| `sshrtauth-force-command` | If present, override the client's exec request with this command. Same semantics as `ForceCommand` in sshd_config. |
| `sshrtauth-environment` | Set the specified environment variables for the session. Same semantics as `SetEnv` in sshd_config. |
| `sshrtauth-max-session` | Start a timer at session establishment. Terminate the session when the timer expires. |
| `sshrtauth-2fa-evidence` | Log the evidence. No enforcement action. |

### Unrecognized critical extensions

If sshd encounters a critical extension it doesn't recognize, it must reject the
cert and deny the connection. This ensures that newer CAs can add new critical
constraints without older sshd implementations silently ignoring them.

### Server-bind validation

sshd needs to know its own canonical name (as registered with the CA) to validate
the `sshrtauth-server-bind` extension. This is configured in the shim's config file
and exposed to sshd via:

```c
/**
 * Returns this server's canonical name as configured in the shim.
 * sshd uses this to validate sshrtauth-server-bind in the auth cert.
 */
const char *ssh_rt_auth_server_name(void);
```

---

## Logging

The shim logs to its own log file (`log.file` in config). Log entries are JSON Lines.

### Log entries

**Cache hit:**
```json
{"ts":"2026-05-11T14:23:07Z","level":"debug","event":"cache_hit","fingerprint":"SHA256:AbCd...","source_ip":"10.0.1.42","serial":"a1b2c3d4"}
```

**Cache miss → CA query:**
```json
{"ts":"2026-05-11T14:23:07Z","level":"info","event":"ca_query","endpoint":"https://ca1.internal:8443","fingerprint":"SHA256:AbCd...","source_ip":"10.0.1.42"}
```

**Authorization granted:**
```json
{"ts":"2026-05-11T14:23:07Z","level":"info","event":"authorized","serial":"a1b2c3d4","fingerprint":"SHA256:AbCd...","source_ip":"10.0.1.42","not_after":"2026-05-11T15:23:07Z"}
```

**Authorization denied:**
```json
{"ts":"2026-05-11T14:23:07Z","level":"info","event":"denied","fingerprint":"SHA256:AbCd...","source_ip":"10.0.1.42","reason":"user not authorized for this server"}
```

**CA failover:**
```json
{"ts":"2026-05-11T14:23:07Z","level":"warn","event":"ca_failover","failed_endpoint":"https://ca1.internal:8443","next_endpoint":"https://ca2.internal:8443","error":"connection timeout"}
```

**Emergency cert used:**
```json
{"ts":"2026-05-11T14:23:07Z","level":"warn","event":"emergency_cert","fingerprint":"SHA256:AbCd...","source_ip":"10.0.1.42"}
```

---

## Error handling summary

| Condition | Shim behavior |
|-----------|---------------|
| Config file missing or invalid | `ssh_rt_auth_init()` returns -1. sshd should refuse to start. |
| mTLS cert/key invalid | `ssh_rt_auth_init()` returns -1. |
| All CA endpoints unreachable | Try emergency cert. If no emergency cert or expired, return -2. |
| CA returns HTTP 403 (denied) | Return -1. |
| CA returns HTTP 5xx (error) | Try next endpoint. If all fail, return -2. |
| CA returns invalid cert | Log error, return -2. Do not cache. |
| CA returns cert with unrecognized critical extension | Log error, return -2. Do not cache. |
| Cache directory unwritable | Log warning, proceed without caching. Queries go to CA every time. |
| Identity blob is empty or malformed | Return -2. Do not query CA. |

---

## PoC implementation plan

### Language

C for the shared library interface (needed for OpenSSH and Dropbear integration).
The PoC may implement the mTLS client and cache logic in C using Mbed TLS, or
use a Python-native shim for the initial prototype and write the C shim later.

For the initial PoC with a Python CA and Python SSH server (Paramiko/AsyncSSH),
a Python-native shim is fastest. The C shim follows once the architecture is validated.

### Files

```
ssh-rt-auth/
  shim/
    ssh_rt_auth.h          # public interface (C header)
    ssh_rt_auth.c          # implementation
    cache.c                # cache logic
    ca_client.c            # mTLS HTTP client, failover
    config.c               # YAML config parsing
    Makefile

  shim-py/
    ssh_rt_auth.py         # Python-native shim (PoC)
    cache.py
    ca_client.py
    config.py

  config/
    config.yaml.example    # example shim config
```

### Build

The C shim builds as a shared library: `libsshrtauth.so` (Linux), `libsshrtauth.dylib` (macOS).
Linked against Mbed TLS for TLS and X.509, and libyaml or a minimal YAML parser for config.

```
make -C shim
# produces shim/libsshrtauth.so
```

### Testing

- Unit tests for cache (insert, lookup, expiry, eviction, malformed entries)
- Unit tests for config parsing (valid, invalid, missing fields)
- Integration test: shim against a mock CA (HTTP server returning canned responses)
- Integration test: shim failover (primary returns error, secondary succeeds)
- Integration test: emergency cert activation (all endpoints unreachable)
- End-to-end test: OpenSSH with shim → real PoC CA → authorized session
