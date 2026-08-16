# ZentLoop Integration Protocol v1

ZentLoop can be the deception backend for unmatched/default traffic from a reverse proxy, ingress controller, load balancer or custom gateway. The protocol is vendor-neutral: integrations only need to route an intentional catch-all target, preserve trustworthy forwarding metadata and attach the headers documented here.

## Routing contract

```text
configured/known route -> normal application backend
unmatched/default route -> ZentLoop HTTP trap
backend/application failure -> normal error handling, never ZentLoop
```

Only intentional catch-all/default traffic should be marked with `X-ZentLoop-Catch-All`. Never use ZentLoop as a generic 4xx/5xx fallback for a configured application whose real upstream is unavailable.

Preserve the original `Host`, validated client forwarding chain and original scheme where the proxy supports them.

## Integration headers

- `X-ZentLoop-Integration`: stable provider/tool identifier, e.g. `zentproxy`, `nginx`, `traefik`, `caddy`, `haproxy`, `edge-gateway`.
- `X-ZentLoop-Target`: original requested host/IP. Optional when the normal `Host` header is preserved.
- For ordinary trusted reverse-proxy paths that rewrite `Host` to ZentLoop's private upstream address, ZentLoop can recover the original host from `X-Forwarded-Host`. In auto mode this is accepted only from a private/loopback proxy peer with independent forwarding evidence (`X-Forwarded-For`, `X-Real-IP`, or valid Cloudflare metadata). `X-Forwarded-Host` alone never establishes trust, and signed target auto-trust remains bound to the exact signed `X-ZentLoop-Target`.
- `X-ZentLoop-Catch-All`: use `1` for catch-all traffic. The standardized examples also use `1` for health checks; the value used is part of the signed canonical payload and must match the header.
- `X-ZentLoop-Timestamp`: Unix timestamp in seconds, required in signed mode.
- `X-ZentLoop-Signature`: `sha256=<hex HMAC>`, required in signed mode.

Integration identifiers are normalized and limited to lowercase letters, digits, `.`, `_` and `-`.

## Trust modes

### Private-peer mode

When `ZENTLOOP_INTEGRATION_SECRET` is empty, integration metadata is accepted only when the immediate TCP peer is private, loopback or link-local. This is intended for containers or gateways on the same trusted Docker/LAN boundary.

Public clients cannot self-mark requests as trusted integration traffic.

### Signed mode

When `ZENTLOOP_INTEGRATION_SECRET` is configured, every trusted integration request must carry a valid HMAC-SHA256 signature, even when the peer address is private.

Canonical payload:

```text
v1
<timestamp>
<integration>
<target>
<catch_all:0|1>
<METHOD>
<request-uri>
```

The request URI includes its query string. The method is uppercase. The target and integration values must be exactly the normalized values represented by the headers.

Signature:

```text
HMAC-SHA256(secret, canonical_payload)
```

Send the lowercase hexadecimal digest as:

```text
X-ZentLoop-Signature: sha256=<hex>
```

The timestamp must be within `ZENTLOOP_INTEGRATION_MAX_SKEW_SECONDS` of ZentLoop's clock. The default is 300 seconds.

### Target auto-trust

Signed integrations may also establish an **exact** trusted target for normal, explicitly routed requests. ZentLoop only auto-trusts `X-ZentLoop-Target` when all of the following are true:

- integration metadata passes HMAC verification;
- `X-ZentLoop-Catch-All` is false/absent;
- the target is a valid domain/IP value.

Private-peer mode never auto-trusts targets, even though its metadata may be accepted for attribution. Catch-all targets also never auto-trust. This is intentional: Docker/NAT boundaries can make external traffic appear to originate from one private peer, and catch-all hosts are commonly attacker-controlled. Auto-trusted proxy targets are visible read-only in the Admin WebUI Trusted Domains settings.

## Health check and integration verification

Integrations should verify ZentLoop independently from normal catch-all traffic before relying on it for routing.

Use:

```text
GET /.well-known/zentloop/integration-check
```

Recommended request headers:

```text
X-ZentLoop-Integration: <tool-name>
X-ZentLoop-Target: <tool-name>-health.invalid
X-ZentLoop-Catch-All: 1
X-ZentLoop-Timestamp: <unix-seconds>
X-ZentLoop-Signature: sha256=<hex-hmac>
```

When no shared secret is configured, the timestamp/signature headers are omitted and the immediate peer still has to satisfy private-peer trust.

The health request uses the same canonical signing format as routed traffic. Example canonical payload for `zentproxy`:

```text
v1
<timestamp>
zentproxy
zentproxy-health.invalid
1
GET
/.well-known/zentloop/integration-check
```

A successful verification returns:

```http
HTTP/1.1 204 No Content
X-ZentLoop-Integration-Verified: 1
```

ZentLoop verifies the health request using the integration metadata/signature. The health endpoint does not depend on the catch-all flag being `1`, but integrations should use the documented example consistently so both sides sign the same canonical value.

A valid health check is intentionally handled before normal deception processing. It creates no normal HTTP session, actor, catch-all statistic, Recent Path entry, Known/Unknown Path entry or ordinary event-log record.

A request that claims an integration identity but fails trust/signature verification is **not hidden**. ZentLoop returns HTTP 403 and records it as normal security traffic. An unclaimed public request to the health path receives a neutral HTTP 404 and is also logged normally.

### Client-side health state

An integrating tool should not treat reachability alone as success. Recommended logic:

1. Connect with short timeouts.
2. Require HTTP `204`.
3. Require `X-ZentLoop-Integration-Verified: 1`.
4. If signed mode is configured, treat HTTP `401/403` as a trust/secret mismatch.
5. Treat a reachable response without the verification header as incompatible/degraded.
6. Treat timeout/refused/unreachable as offline.
7. Fail closed for explicit ZentLoop routes when the configured trust policy is not satisfied.

A 15-30 second health interval is appropriate for most local proxy integrations. ZentLoop displays a peer as `verified` when recently seen, `stale` after 45 seconds without a successful verification and `offline` after 90 seconds.

### Common integration mistakes

- Checking only HTTP reachability/status and ignoring `X-ZentLoop-Integration-Verified`.
- Using a different field order or extra newline in the canonical HMAC payload.
- Forgetting the query string when signing a normal routed request.
- Signing a different target than the value sent in `X-ZentLoop-Target`.
- Omitting or changing `X-ZentLoop-Catch-All: 1` for the standardized health request.
- Using milliseconds instead of Unix seconds in `X-ZentLoop-Timestamp`.
- Loading the shared secret with accidental whitespace/newlines.
- Logging the shared secret, signature input or credentials in an integration UI.
- Sending health checks through the normal public catch-all route instead of the private/internal ZentLoop upstream.
- Treating an unavailable configured application upstream as a reason to route that application request into ZentLoop.

## Implementation checklist

An external tool needs only these capabilities:

1. Define a default/unmatched route whose upstream is the ZentLoop HTTP trap.
2. Keep normal configured routes pointed at their real backends.
3. Preserve the original host and validated client IP/protocol metadata where supported.
4. Set a stable `X-ZentLoop-Integration` identifier.
5. Mark only intended ZentLoop routing with `X-ZentLoop-Catch-All: 1`.
6. Optionally send `X-ZentLoop-Target` when the original `Host` cannot be preserved.
7. Use signed mode whenever the immediate proxy-to-ZentLoop network boundary is not fully trusted.
8. Implement the health-verification flow above and require the verification response before declaring the integration healthy.

`integrations/nginx.md` remains a concrete example of the generic routing contract. The health-verification section in this document is authoritative for every integration.

## Discovery and admin status

The authenticated admin endpoint:

```text
GET /api/integration
```

returns protocol version, capabilities, accepted headers, signing policy and health-verification metadata. It never returns the configured secret.

Verified integration peers are available through:

```text
GET /api/integration/peers
```

and are shown in the WebUI under **Connected integrations**. Peer state contains the integration name, immediate source IP, trust mode, first/last verification time, status and aggregate check/failure counters. Secrets and signatures are never exposed.

## Catch-all statistics

Only requests carrying trusted integration metadata with `X-ZentLoop-Catch-All: 1` enter catch-all host statistics. Health verification is excluded from those statistics.

The admin API provides:

```text
GET /api/catchall-hosts
GET /api/catchall-hosts.csv
```
