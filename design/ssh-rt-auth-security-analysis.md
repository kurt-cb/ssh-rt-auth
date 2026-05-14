# ssh-rt-auth Security Analysis

**Project:** ssh-rt-auth (runtime, CA-mediated SSH authorization)  
**Status:** Design review v0.1  
**Author:** Kurt Godwin (github.com/kurt-cb)  
**Audience:** Security engineers, cryptographers, protocol reviewers  
**Scope:** Threat model, attack surface analysis, cryptographic properties, standards conformance  

---

## 1. System model

ssh-rt-auth separates SSH authentication from authorization. Authentication (proving
identity) happens at the SSH transport layer using standard mechanisms defined in
RFC 4252 (SSH Authentication Protocol). Authorization (granting access) happens at
a separate CA that issues short-lived X.509v3 certificates over an mTLS side channel.

The system has four principals:

- **Client:** Unmodified SSH client. Holds a long-lived private key or an OpenSSH
  user certificate. Connects via standard SSHv2 (RFC 4253).
- **Server:** Runs a patched SSH daemon with the ssh-rt-auth shim. Holds an mTLS
  client certificate for authenticating to the CA.
- **Authorization CA:** Issues X.509 authorization certificates. Holds the CA
  signing key. Reachable only from enrolled servers over mTLS (RFC 8446).
- **Administrator:** Holds an admin mTLS certificate. Manages enrollment via the
  CA's admin API.

Three independent trust roots:

1. **User identity trust root:** Public key of the CA that signs OpenSSH user
   certificates (RFC 4253 §6.6, OpenSSH PROTOCOL.certkeys). Only relevant for
   the `openssh-cert` identity proof type.
2. **Server/admin identity trust root:** X.509 CA certificate used to sign
   server and admin mTLS client certificates (RFC 5280).
3. **Authorization signing key:** The authorization CA's own key pair, used to
   sign X.509 authorization certificates containing policy extensions.

---

## 2. Cryptographic primitives and standards

### 2.1 Transport security

All CA communication uses TLS 1.3 (RFC 8446) with mutual authentication (mTLS).
Both sides present X.509 certificates. The TLS implementation must enforce:

- **Minimum protocol version:** TLS 1.3. TLS 1.2 is acceptable only for the PoC;
  production deployments must require TLS 1.3 to eliminate downgrade attacks and
  ensure forward secrecy via ephemeral key exchange (x25519 or secp256r1).
- **Cipher suite restriction:** TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
  TLS_AES_128_GCM_SHA256. No CBC-mode suites.
- **Certificate validation:** Full chain validation per RFC 5280 §6. No wildcard
  matching on client certificates. Subject CN or SAN must match the enrollment
  database entry.
- **Certificate pinning:** The shim pins the CA's server certificate (or its
  trust root) rather than relying on system trust stores. This prevents rogue CA
  certificates from OS or browser trust stores from being accepted.

### 2.2 SSH authentication

Client authentication follows RFC 4252 §7 (public key authentication) and
OpenSSH's certificate extension (PROTOCOL.certkeys). The SSH daemon performs
standard signature verification:

- **Bare public key:** Client proves possession of the private key by signing
  the SSH session identifier (H) concatenated with a `SSH_MSG_USERAUTH_REQUEST`
  message (RFC 4252 §7). The server verifies the signature against the presented
  public key.
- **OpenSSH certificate:** The server validates the certificate signature against
  a configured user CA public key, checks validity window, checks principals,
  then verifies the client's possession signature. The raw certificate blob
  (including all fields: nonce, public key, serial, type, key-id, principals,
  validity, critical options, extensions, signing key, signature) is forwarded
  to the authorization CA for independent validation.

Supported key types: ssh-ed25519 (RFC 8709), ecdsa-sha2-nistp256/384/521
(RFC 5656), ssh-rsa with SHA-256/512 signatures (RFC 8332). DSA keys
(ssh-dss) are not supported.

### 2.3 Authorization certificate

The authorization certificate is X.509v3 (RFC 5280) with private-use extensions
under a registered OID arc (1.3.6.1.4.1.XXXXX). Extensions are DER-encoded ASN.1
per X.690.

**Signing algorithms:**

- Ed25519 (RFC 8032) — preferred
- ECDSA P-256 with SHA-256 (FIPS 186-4, RFC 6979 for deterministic signatures)
- RSA is explicitly unsupported for the CA signing key

**Serial numbers:** Cryptographically random 128-bit values (per RFC 5280 §4.1.2.2
recommendation and CA/Browser Forum Baseline Requirements §7.1). Monotonic counters
are acceptable for the PoC but must not be used in production due to predictability.

**Validity windows:** notBefore is the current time; notAfter is bounded by the
policy's `max_cert_validity_seconds` (range: 60–86400 seconds). Short validity is
the primary revocation mechanism (see §4.5).

### 2.4 Key storage

| Key | Storage | Protection |
|-----|---------|------------|
| CA signing key | File on CA host (PoC), HSM (production) | File permissions 0600, encrypted at rest (production). HSM-backed keys never leave the HSM boundary. |
| mTLS CA private key | File on CA host | File permissions 0600. Used to sign server/admin mTLS certs. |
| Server mTLS private key | File on each server | File permissions 0600, readable only by the sshd/shim process. |
| Admin mTLS private key | File on admin workstation | File permissions 0600. Should be password-protected (PKCS#8 encryption). |
| Client SSH private key | Client's `~/.ssh/` | Standard SSH key protection (passphrase, ssh-agent, FIDO2/PIV). |
| Bootstrap admin key | Generated at CA init | Must be moved to secure storage (HSM, safe) after initial setup. |

---

## 3. Threat model

### 3.1 Threat actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **External attacker** | Network access to the client's network. No access to the server's management network. May have stolen client credentials. | Gain unauthorized SSH access to servers. |
| **Compromised client** | Full control of a client machine. Has the client's SSH private key. | Escalate from client access to server access. |
| **Compromised server** | Root access to one enrolled server. Has that server's mTLS cert and cached authorization certs. | Lateral movement to other servers. Access to the CA. |
| **Compromised admin** | Has a valid admin mTLS cert. | Modify enrollment to grant unauthorized access. |
| **Insider threat** | Legitimate user with valid credentials. | Exceed authorized access (wrong servers, wrong times, wrong channels). |
| **Network adversary** | Can observe, inject, and modify traffic on any network segment. | MITM the CA channel, replay authorization certs, extract secrets from traffic. |

### 3.2 Assumptions

- The CA host is trusted. If the CA signing key is compromised, the entire system
  is compromised. This is inherent to any CA-based architecture.
- The management network (CA ↔ servers) is not assumed to be secure against
  eavesdropping — mTLS provides confidentiality and integrity.
- The client network is untrusted.
- DNS is not trusted for identity (DNSSEC is required for name resolution, but
  server identity is established via mTLS certificates, not DNS names).
- SSH forward secrecy (RFC 4253 §8) protects recorded traffic from future key
  compromise. A stolen private key enables real-time impersonation but does not
  enable decryption of previously recorded sessions. These are distinct properties.

---

## 4. Attack vector analysis

### 4.1 Stolen client credential

**Attack:** Attacker exfiltrates a user's SSH private key from their workstation
(malware, physical access, backup exposure).

**Traditional defense (client-held cert systems):** Short certificate validity
bounds the damage window. Attacker can impersonate the user until the cert expires
(seconds to hours). If the cert is long-lived, the damage window is long.

**ssh-rt-auth defense:** The stolen private key alone is insufficient. The attacker
must also be able to reach a server that will query the CA on their behalf. Since
the CA is on a management network unreachable from the attacker's position, the
authorization query never completes.

**Defense strength:** This is a *structural* defense, not a *temporal* one. It does
not depend on cert validity windows, revocation propagation delays, or OCSP
responder availability. It depends on network segmentation. If the attacker can
reach a server's SSH port, they can authenticate (the server validates their
signature), but the server's authorization query to the CA succeeds and the attacker
gets access. The defense holds only when the attacker cannot reach a legitimate
server.

**Residual risk:** If the attacker gains network access to a server's SSH port
(e.g., through a VPN compromise, a jump host, or a misconfigured firewall), the
stolen credential grants access. At that point, the system falls back to
policy-based defenses: source IP restrictions (`sshrtauth-source-bind`), time
window restrictions, channel restrictions.

**Mitigation of residual risk:** Deploy the CA on a network segment that is
unreachable from the VPN/jump-host subnet. Use source CIDR policies that restrict
access to known-good subnets. Require OpenSSH certificate identity (not bare keys)
to limit the window of key validity.

### 4.2 Compromised server — lateral movement

**Attack:** Attacker gains root on server A. They want to move laterally to
server B.

**What the attacker has:**

- Server A's mTLS client certificate and private key
- Cached authorization certs for users who recently connected to server A
- Server A's SSH host key and host certificate

**What they can attempt:**

1. **Use server A's mTLS cert to query the CA for authorization to server B:**
   Fails. The CA identifies the calling server from its mTLS cert. Server A's
   cert is enrolled as server A. When the CA evaluates policy, it checks whether
   the user is authorized to access *server A*, not server B. The
   `sshrtauth-server-bind` extension in the returned cert is set to server A's
   canonical name. Even if the attacker could present this cert to server B,
   server B would reject it because the server-bind doesn't match.

2. **Replay a cached authorization cert from server A to server B:**
   Fails. The cached cert contains `sshrtauth-server-bind = "server-A"`.
   Server B validates this extension and rejects the cert because the bind
   doesn't match server B's canonical name. Additionally, `sshrtauth-source-bind`
   ties the cert to a specific client IP, which the attacker connecting from
   server A wouldn't match.

3. **Impersonate a user to the CA using their cached cert:**
   Not applicable. The authorization cert is issued *to* the server, not *by*
   the user. The attacker cannot use a cached authorization cert to authenticate
   as a user to any other server. The cert proves that the CA authorized user X
   to access server A; it doesn't prove that the attacker is user X.

4. **Steal a user's SSH private key from server A:**
   Not applicable. The user's SSH private key never reaches the server. SSH
   public key authentication (RFC 4252 §7) proves key possession via a
   challenge-response signature; the private key stays on the client.

**Defense strength:** Strong against lateral movement via the authorization
system. The attacker must compromise each target server independently or find
a path that doesn't involve ssh-rt-auth (e.g., exploiting a vulnerability in
the target server's services).

### 4.3 Compromised CA

**Attack:** Attacker gains access to the CA signing key.

**Impact:** Total system compromise. The attacker can mint arbitrary authorization
certificates for any user to any server with any policy. There is no defense
against a compromised CA — this is inherent to any CA-based architecture.

**Mitigations:**

- **HSM-backed signing key:** The CA signing key should be stored in an HSM
  (PKCS#11, AWS CloudHSM, YubiHSM) in production. The key never leaves the
  HSM boundary; signing operations are performed by the HSM.
- **Audit logging:** Every authorization cert issuance is logged with full
  context. Anomalous issuance patterns (unknown users, unusual servers, unusual
  times) can be detected by monitoring.
- **Network isolation:** The CA host should be on the most restricted network
  segment. SSH access to the CA host should require the emergency cert or
  physical/console access.
- **Key ceremony:** CA signing key generation should follow a key ceremony
  process with witnesses, documented procedures, and hardware-verified entropy
  sources.

### 4.4 Man-in-the-middle on the CA channel

**Attack:** Network adversary intercepts traffic between the shim and the CA.

**Defense:** mTLS (RFC 8446). Both sides authenticate. The shim pins the CA's
certificate or trust root, preventing substitution. TLS 1.3 provides forward
secrecy via ephemeral Diffie-Hellman key exchange; recording the mTLS traffic
does not allow later decryption even if long-term keys are compromised.

**Defense strength:** Standard TLS 1.3 security guarantees apply. The security
reduces to the difficulty of breaking the TLS handshake, which is well-studied.
Certificate pinning eliminates reliance on third-party CAs.

### 4.5 Authorization cert replay

**Attack:** Attacker obtains an authorization cert (from a server's cache, from
network capture, from memory dump) and attempts to use it on a different
connection.

**Defenses (layered):**

1. **Server binding (`sshrtauth-server-bind`, critical extension):** The cert is
   valid only for the server whose canonical name matches. Replaying to a
   different server fails validation.

2. **Source binding (`sshrtauth-source-bind`, critical extension):** The cert is
   valid only from the source IP that the CA specified. Replaying from a
   different IP fails validation.

3. **Short validity window (notBefore/notAfter):** Typical validity is seconds
   to hours. The replay window is bounded by the cert's expiry.

4. **TLS channel binding:** The authorization cert is delivered inside a TLS 1.3
   session between the shim and the CA. An attacker who captures the cert from
   the TLS channel would need to break TLS encryption first.

5. **Cache isolation:** The cert is cached on disk with restricted file permissions
   (0600, owned by the sshd/shim process). An attacker with root access to the
   server can read it, but at that point they already control the server (see §4.2).

**Defense strength:** Replay across servers is structurally prevented by server
binding. Replay from different IPs is prevented by source binding. Replay within
the validity window from the same server and IP is theoretically possible but
requires the attacker to already have a position on the server — at which point
they already have access. The defense degrades gracefully: even if one binding
is bypassed, the others still apply.

### 4.6 Denial of service against the CA

**Attack:** Attacker floods the CA with authorization requests to prevent
legitimate servers from getting authorization certs.

**Impact:** If the CA is unreachable, all new SSH connections are denied
(fail-closed). Existing sessions with valid cached certs continue. The admin
emergency cert provides break-glass access.

**Mitigations:**

- **Network isolation:** The CA is reachable only from enrolled servers on the
  management network. Unenrolled hosts cannot reach the CA's port. The DoS
  surface is limited to compromised or misconfigured servers.
- **mTLS as access control:** The CA rejects connections from clients without
  valid mTLS certs at the TLS layer, before processing any application-level
  requests. Invalid TLS handshakes consume minimal resources.
- **Rate limiting per server:** The CA can rate-limit authorization requests
  per mTLS client cert. A compromised server can be throttled without affecting
  other servers.
- **CA failover:** The shim supports multiple CA endpoints. A DoS against one
  CA instance doesn't prevent access if a secondary instance is available.

### 4.7 Compromised admin credential

**Attack:** Attacker obtains an admin mTLS certificate and private key.

**Impact depends on the admin's role:**

| Role | Impact |
|------|--------|
| `auditor` | Read-only access to enrollment and audit logs. No ability to modify policy. Information disclosure only. |
| `server-admin` | Can enroll new servers and modify server groups. Cannot create users or policies. Could register a malicious server, but cannot authorize any user to it without `user-admin` privileges. |
| `user-admin` | Can create users, add keys, create policies. Could grant an attacker's key access to enrolled servers. This is the high-impact admin role. |
| `superuser` | Full compromise of the admin interface. Can create new superusers, enroll arbitrary servers and users, modify all policies. |

**Mitigations:**

- **Role separation:** Use the minimum role needed. Most admins should be
  `server-admin` or `user-admin`, not `superuser`.
- **Admin cert protection:** Admin private keys should be password-protected
  (PKCS#8) and stored on the admin's workstation with restricted permissions.
  For `superuser` certs, HSM/smartcard storage is recommended.
- **Audit trail:** Every admin action is logged with the admin's identity, role,
  and the action performed. Admin actions are detectable and attributable.
- **Bootstrap cert security:** The initial `superuser` cert generated at CA init
  must be stored securely (HSM, physical safe) after initial setup. It should
  not reside on any networked system during normal operations.

### 4.8 Rogue SSH server

**Attack:** Attacker deploys a rogue SSH server on the network, convinces
clients to connect to it.

**Impact on ssh-rt-auth:** None, unless the rogue server has a valid mTLS cert.
Without an mTLS cert, the rogue server cannot query the CA. Without an
authorization cert from the CA, the rogue server cannot participate in the
ssh-rt-auth system. The attacker could capture the client's SSH userauth
signature, but this signature is bound to the SSH session identifier (H) and
cannot be replayed to a different server (this is a property of SSH, not of
ssh-rt-auth).

**Residual risk:** The rogue server could capture the client's username and
public key (both are sent in cleartext during SSH userauth). This is information
disclosure, not credential theft — the public key is, by definition, public.

### 4.9 Cache poisoning

**Attack:** Attacker writes a malicious authorization cert to the shim's cache
directory.

**Requirements:** Root access to the server (cache directory is 0700, owned by
the sshd/shim process).

**Defense:** The shim validates every cached cert before use:

1. Verify the cert's signature against the authorization CA trust root
2. Check notBefore ≤ now ≤ notAfter
3. Check `sshrtauth-server-bind` matches this server's canonical name
4. Check for unrecognized critical extensions → reject

A malicious cert without a valid CA signature fails step 1. The attacker would
need the CA signing key to produce a cert that passes validation — at which
point they have a CA compromise (§4.3), not merely a cache poisoning.

**Defense strength:** Strong. Cache poisoning without CA key compromise is
not viable.

### 4.10 Time-based attacks

**Attack:** Attacker manipulates the server's clock to extend the validity of
a cached authorization cert, or to bypass time-window restrictions in policy.

**Defenses:**

- **Timestamp drift check:** The CA rejects authorization requests where the
  server's timestamp differs from the CA's clock by more than a configurable
  threshold (default: 60 seconds). This prevents grossly incorrect clocks
  from receiving valid certs.
- **NTP/DNSSEC requirement:** Servers should use authenticated time sources
  (NTS per RFC 8915, or DNSSEC-authenticated NTP).
- **Cert validity is CA-controlled:** The notBefore/notAfter in the authorization
  cert are set by the CA using the CA's clock, not the server's. A server with
  a skewed clock still receives certs with validity windows based on the CA's
  time.

**Residual risk:** If an attacker can manipulate the server's clock *after*
receiving a valid cert, they could extend the apparent validity of the cached
cert by moving the clock backward. This requires root access to the server,
which implies the server is already compromised (§4.2).

### 4.11 OpenSSH certificate trust chain confusion

**Attack:** Attacker presents an OpenSSH user certificate signed by a CA that
is trusted for identity but should not grant access to the target server.

**Defense:** The authorization CA performs independent trust chain validation.
The CA maintains its own list of trusted identity CAs and validates the
OpenSSH certificate signature against this list. The CA does not rely on the
SSH server's trust configuration. Policy evaluation (which users are authorized
to which servers) is separate from identity validation (is this a valid cert
from a trusted CA). A valid identity cert from a trusted CA only proves who
the user is; it does not grant access — that requires a matching policy.

### 4.12 Emergency cert abuse

**Attack:** An attacker obtains the emergency cert and uses it to bypass the
CA entirely.

**Impact:** The emergency cert is a long-lived, client-held authorization cert
that servers accept when the CA is unreachable. It is the intentional exception
to the "no client-held authorization" rule. If stolen, it provides access to
any server configured to accept emergency certs.

**Mitigations:**

- **Separate trust root:** Emergency certs are validated against a different
  trust root than CA-issued authorization certs. Compromising the CA signing
  key does not compromise the emergency trust root, and vice versa.
- **HSM/physical storage:** The emergency cert and its private key should be
  stored in an HSM or physical safe. Not on any networked system.
- **Limited scope:** Servers can be configured to not accept emergency certs
  at all (high-security environments where CA availability is guaranteed).
- **Audit alerting:** Use of an emergency cert should trigger an immediate
  security alert, since it indicates either CA failure or misuse.

---

## 5. Cryptographic properties summary

| Property | Mechanism | Standard |
|----------|-----------|----------|
| Client authentication | SSH public key signature over session ID | RFC 4252 §7 |
| Client identity (cert) | OpenSSH certificate validation | OpenSSH PROTOCOL.certkeys |
| Transport confidentiality | TLS 1.3 with AEAD ciphers | RFC 8446 |
| Transport integrity | TLS 1.3 record layer | RFC 8446 |
| Forward secrecy (SSH) | Ephemeral DH key exchange | RFC 4253 §8, RFC 9142 |
| Forward secrecy (CA channel) | TLS 1.3 ephemeral key exchange | RFC 8446 §2 |
| Server authentication to CA | mTLS client certificate | RFC 5280, RFC 8446 |
| CA authentication to server | TLS server certificate (pinned) | RFC 5280, RFC 8446 |
| Authorization binding | X.509v3 cert with critical extensions | RFC 5280 §4.2 |
| Authorization freshness | Short cert validity (seconds to hours) | RFC 5280 §4.1.2.5 |
| Source binding | IP/CIDR in critical X.509 extension | Custom (private OID arc) |
| Server binding | Canonical name in critical X.509 extension | Custom (private OID arc) |
| Cert signature | Ed25519 or ECDSA P-256 | RFC 8032, FIPS 186-4 |
| Serial uniqueness | 128-bit CSPRNG | RFC 5280 §4.1.2.2, RFC 4086 |
| Audit correlation | Cert serial as session handle | — |
| Admin authentication | mTLS client certificate with role lookup | RFC 5280, RFC 8446 |

---

## 6. Comparison with existing systems

### 6.1 vs. OpenSSH certificates (vanilla)

OpenSSH certificates (PROTOCOL.certkeys) put the authorization cert on the client.
The cert carries principals, validity, critical options, and extensions. The defense
against credential theft is short cert validity.

ssh-rt-auth moves the authorization cert to the server's cache, making stolen client
credentials insufficient without CA reachability. The tradeoff: dependency on CA
availability (mitigated by the emergency cert and CA failover).

### 6.2 vs. Smallstep step-ca

Smallstep's step-ca issues short-lived SSH certificates to clients after OIDC or
other identity verification. The client holds the cert. ssh-rt-auth's architecture
is structurally different: the client never holds an authorization cert.

Smallstep's single-intermediate-CA and passive-revocation limitations (documented
in their OSS release) do not apply to ssh-rt-auth's design, since the authorization
cert is server-cached and CA-controlled.

### 6.3 vs. HashiCorp Vault SSH

Vault's SSH secrets engine issues signed SSH certificates (client-held) after
authentication to Vault. Like step-ca, the cert is on the client. Vault adds
enterprise features (namespaces, Sentinel policies) that ssh-rt-auth does not
need — ssh-rt-auth's policy engine is deliberately simple and runs on two Alpine
boxes without internet connectivity.

### 6.4 vs. Teleport

Teleport is a full access management platform with a proxy, auth service, and
agents. It records sessions, manages RBAC, and provides a web UI. ssh-rt-auth
is architecturally minimal: only the CA and the modified sshd. No proxy, no
agents, no web UI. Teleport requires infrastructure that ssh-rt-auth explicitly
avoids.

ssh-rt-auth's session logging is command-level (intent, not content). Teleport
provides byte-stream session recording, which ssh-rt-auth considers a non-goal.

---

## 7. Known limitations and honest tradeoffs

1. **CA availability is a single point of failure.** If all CA instances are
   unreachable and the emergency cert is not available, no new SSH connections
   succeed. This is the fundamental tradeoff for the CA-isolation defense.
   Mitigation: multiple CA instances with failover; emergency cert for break-glass.

2. **Revocation is by expiration only.** There is no CRL or OCSP mechanism.
   When a user is de-enrolled from the CA, existing cached authorization certs
   for that user remain valid until their TTL expires (seconds to hours). For
   immediate revocation, the cert validity must be short enough that the
   exposure window is acceptable, or servers must be signaled to flush their
   caches (not currently in the design).

3. **The emergency cert is a bearer credential.** It is the one client-held
   authorization in the system and is vulnerable to theft. Its security depends
   on physical/HSM storage discipline, not on architectural properties.

4. **Server compromise exposes cached certs.** An attacker with root on a server
   can read the cache directory. The cached certs are scoped (server-bound,
   source-bound, time-limited) but are readable. This is equivalent to an
   attacker with root reading `/etc/ssh/authorized_keys` in traditional SSH —
   root on the server is game over for that server.

5. **No protection against compromised CA.** This is inherent to any CA-based
   architecture and not specific to ssh-rt-auth. HSM-backed signing keys
   reduce the risk but do not eliminate it.

6. **Hop chain attestation is absent.** The predecessor mssh project designed
   user-driven hop chain attestation. With unmodified SSH clients, this is not
   possible. An SSH session that traverses multiple hops (via ProxyJump or
   similar) does not carry attestation of the intermediate hops. This is a
   structural limitation of the unmodified-client constraint.

7. **Policy evaluation is not formally verified.** The policy engine is
   implemented in application code. Logic errors in policy evaluation (incorrect
   CIDR matching, time zone handling bugs, policy merge logic errors) could
   result in over-authorization. Mitigation: policy evaluation is simple and
   linear, amenable to thorough testing. The cert's critical extensions provide
   a second enforcement layer at the server.

---

## 8. Recommendations for production hardening

1. **HSM for CA signing key.** Do not store the CA signing key in a file on disk
   for production deployments. Use PKCS#11-compatible HSMs (YubiHSM 2, AWS
   CloudHSM, Thales Luna) or TPM 2.0 with PKCS#11 bindings.

2. **Certificate transparency log.** Implement a private CT-style log (RFC 9162
   concepts, not necessarily public CT infrastructure) for authorization certs.
   Every issued cert is appended to an append-only log that auditors can verify.
   Detects unauthorized issuance even if the CA is partially compromised.

3. **Rate anomaly detection.** Monitor the audit log for anomalous patterns:
   authorization requests at unusual times, from unusual IPs, for unusual
   user/server combinations. This complements the structural defenses with
   behavioral detection.

4. **Admin cert rotation.** Enforce admin cert expiry (e.g., 90 days) and
   require re-issuance. Revoke admin certs when personnel change roles. The
   admin enrollment database should be reviewed periodically.

5. **Cache integrity monitoring.** On high-security servers, monitor the cache
   directory for unexpected modifications (file integrity monitoring,
   inotify/auditd). Detects cache poisoning attempts even though they
   wouldn't survive cert validation.

6. **Network segmentation verification.** Periodically verify that the CA is
   unreachable from untrusted networks. The structural defense depends on
   network isolation; misconfigurations silently degrade it.

7. **Formal OID registration.** Register a private enterprise number (PEN) with
   IANA for the custom X.509 extensions. Using experimental or unregistered
   OID arcs in production risks collision with other private-use extensions.

8. **Authenticated time.** Deploy NTS (RFC 8915) or DNSSEC-authenticated NTP
   on all servers and the CA. Time-based policy checks are only as trustworthy
   as the clocks they rely on.
