# Nginx catch-all example

This file is an **implementation example**, not a ZentLoop dependency on Nginx. The integration contract itself is proxy- and gateway-neutral and is documented in `../INTEGRATION_PROTOCOL.md`.

The general routing rule for any product is:

```text
configured/known route -> normal application backend
unmatched/default route -> ZentLoop HTTP trap
backend/application failure -> normal error handling, never ZentLoop
```

An integrating proxy or gateway should preserve the original request metadata where possible and mark only its intentional catch-all/default route as ZentLoop traffic.

Minimum useful metadata:

```text
Host: <original requested host>
X-Forwarded-For: <validated visitor chain>
X-Forwarded-Proto: <original scheme>
X-ZentLoop-Integration: <stable provider/tool identifier>
X-ZentLoop-Target: <original requested host, optional when Host is preserved>
X-ZentLoop-Catch-All: 1
```

## Nginx example

```nginx
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header X-ZentLoop-Integration nginx;
        proxy_set_header X-ZentLoop-Target $host;
        proxy_set_header X-ZentLoop-Catch-All 1;

        proxy_pass http://zentloop:8080;
    }
}
```

## Implementing the same contract in another tool

A reverse proxy, load balancer, ingress controller or custom gateway does not need ZentLoop-specific runtime code. It only needs to provide an equivalent default/unmatched route and the metadata above.

For a private same-host Docker/LAN peer, unsigned integration metadata can be used while `ZENTLOOP_INTEGRATION_SECRET` is empty. If the proxy-to-ZentLoop boundary is not fully trusted, use protocol v1 signed mode instead. Signed mode adds `X-ZentLoop-Timestamp` and `X-ZentLoop-Signature` using the canonical HMAC payload in `../INTEGRATION_PROTOCOL.md`.

An integration can query the authenticated admin endpoint `GET /api/integration` to discover the supported protocol version, headers and signing policy. Do not route ordinary upstream errors to ZentLoop; only intentional unmatched/default traffic belongs in the catch-all dataset.

## Health verification

Do not use a normal catch-all request as a health signal. Integrations should verify ZentLoop through the standardized endpoint:

```text
GET /.well-known/zentloop/integration-check
```

In signed deployments, calculate `X-ZentLoop-Signature` with the same HMAC-SHA256 canonical format used for routed requests and require both HTTP `204` and:

```text
X-ZentLoop-Integration-Verified: 1
```

A reachable response without that confirmation must not be treated as a healthy signed integration. See `../INTEGRATION_PROTOCOL.md` for the complete health-check contract, timing guidance and failure behavior.
