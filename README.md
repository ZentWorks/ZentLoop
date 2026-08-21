<p align="center">
  <img src="assets/zentloop-logo.png" alt="ZentLoop" width="180">
</p>

# ZentLoop

**Development State:** Active Development

ZentLoop is a Docker-first deception and honeypot platform for observing hostile HTTP and SSH activity without giving visitors a real shell, real filesystem access or attacker-directed outbound network access.

It combines an HTTP deception trap, an optional fully virtual SSH **Rabbit Hole**, actor/session correlation, live observability and reverse-proxy catch-all integration in one service.

> **Security boundary:** SSH commands, simulated downloads, nested SSH, interpreters, shell operators and synthetic internal services are handled by ZentLoop's virtual engine. They are not delegated to a real operating-system shell and do not execute attacker-controlled code on the host.

## Features

- HTTP deception for scanner, bot and exploit-path activity
- Adaptive scanner-fed Web families keep WordPress/Rails/PHP discoveries story-consistent instead of making every probed technology exist at once
- Optional SSH deception listener with a fully virtual filesystem and command environment
- Shared synthetic world across HTTP and SSH
- Actor intelligence with compact Web + SSH cross-protocol observations
- Evidence-backed Attack Traces only when ZentLoop can prove a direct deception follow or synthetic canary reuse
- Dedicated per-IP intelligence view with Web/SSH statistics, hardened heuristic campaign correlation and one JSON export
- SSH highlights and unified Web/SSH realtime session observability
- Responsive Web administration interface with first-party login sessions, Live/Intelligence drawers and iPhone/iPad home-screen Web App metadata
- Optional read-only management SSH view for the live TUI
- Reverse-proxy catch-all / sink-backend integration
- Cloudflare, generic reverse-proxy and direct-IP attribution modes
- Passive GeoIP and official crawler verification
- Persistent event/session data in `/data`
- Docker Compose deployment
- Multi-architecture images for `linux/amd64` and `linux/arm64`

## Container image

The production image is published to GitHub Container Registry:

```text
ghcr.io/zentworks/zentloop:latest
```


## Quick start with Docker Compose

Create a directory:

```bash
mkdir zentloop
cd zentloop
```

Download or create the repository `compose.yaml` and copy the example environment file:

```bash
cp .env.example .env
```

You can optionally set a stable administrator password in `.env`:

```dotenv
ZENTLOOP_ADMIN_USER=admin
ZENTLOOP_ADMIN_PASSWORD=replace-with-a-long-random-password
```

If `ZENTLOOP_ADMIN_PASSWORD` is empty or unset, ZentLoop generates a cryptographically random administrator password on every start and prints it to the container log. Set the variable yourself if the password should remain stable across restarts.

The browser Admin UI presents its own login page instead of the browser Basic-Auth popup. A successful login creates a temporary in-memory HttpOnly session; use a TLS reverse proxy or trusted VPN for remote administration.

The Admin footer notifies you when a newer stable ZentLoop release is available.

Start ZentLoop:

```bash
docker compose up -d
```

View logs:

```bash
docker compose logs -f zentloop
```

With the default bridge configuration:

```text
HTTP trap:   http://<docker-host>:8080
Web admin:   http://127.0.0.1:9090
SSH trap:    host TCP/2222 -> container TCP/22
Admin SSH:   host TCP/22222 -> container TCP/22222, loopback only
```

The SSH listeners are disabled until explicitly enabled through environment variables.

## Docker CLI

A minimal HTTP-only deployment can also be started directly:

```bash
docker run -d \
  --name zentloop \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 127.0.0.1:9090:9090 \
  -e ZENTLOOP_ADMIN_USER=admin \
  -e ZENTLOOP_DATA_DIR=/data \
  -v zentloop-data:/data \
  ghcr.io/zentworks/zentloop:latest
```

For production use, keep the administration interface private and use the hardened Compose configuration as the reference deployment.

## SSH Rabbit Hole

Enable the public SSH deception listener with:

```dotenv
ZENTLOOP_SSH_ENABLED=true
ZENTLOOP_SSH_ADDR=0.0.0.0:22
ZENTLOOP_SSH_PUBLIC_PORT=2222
ZENTLOOP_SSH_HOST_KEY_PATH=/data/ssh_trap_host_ed25519_key
```

The generic Docker bridge example uses host TCP/2222 so it does not accidentally replace the Docker host's real SSH service on TCP/22. With a dedicated ZentLoop IP, the trap can instead listen on TCP/22 on that address.

ZentLoop's SSH environment is synthetic. It simulates reconnaissance, files, processes, services, shell state, downloads and common operator workflows while keeping execution inside the deception engine. TCP forwarding, agent forwarding, X11 and SFTP/subsystems are rejected.

Clearly aggressive repeat SSH sources may receive a small bounded, jittered banner delay. This adaptive tarpit is capped at three seconds, uses a separate small semaphore and never changes credential acceptance or exposes a real shell.

SSH passwords are not persisted. Authentication telemetry records metadata such as username, authentication method, password presence/length and client banner.

## Management SSH

A separate management SSH endpoint can open ZentLoop's live TUI directly:

```dotenv
ZENTLOOP_ADMIN_SSH_ENABLED=true
ZENTLOOP_ADMIN_SSH_ADDR=0.0.0.0:22222
ZENTLOOP_ADMIN_SSH_USER=admin
ZENTLOOP_ADMIN_SSH_AUTHORIZED_KEY="ssh-ed25519 AAAA... comment"
```

Management SSH uses public-key authentication and does not expose a system shell, command execution, SCP/SFTP, agent forwarding or TCP forwarding. Keep it restricted to a trusted LAN or VPN.

## Reverse-proxy catch-all integration

ZentLoop can be used as a fallback/sink backend for **unmatched hosts** behind a reverse proxy. Known production hosts should continue to their normal applications; only unknown/unconfigured destinations should be routed to ZentLoop.

Do not use ZentLoop as a generic fallback for application errors from valid production hosts.

Integration metadata can be authenticated with one or more shared secrets:

```dotenv
# One secret
ZENTLOOP_INTEGRATION_SECRET="eins"

# Multiple accepted secrets (one quoted comma-separated value)
ZENTLOOP_INTEGRATION_SECRET="eins,zwe!,dr3i"
ZENTLOOP_INTEGRATION_MAX_SKEW_SECONDS=300
```

Each incoming signed request may use any configured secret. Commas delimit secrets and cannot be part of an individual secret. **Connected integrations** keeps same-name peers separate by source and matched `key-N` slot without exposing the secret itself.

The protocol and health-check behavior are documented in [docs/INTEGRATION_PROTOCOL.md](docs/INTEGRATION_PROTOCOL.md). Nginx-specific integration notes are available under [docs/integrations/](docs/integrations/).

## Proxy modes

ZentLoop supports:

```dotenv
ZENTLOOP_PROXY_MODE=auto
# direct | generic | cloudflare
```

`auto` is recommended for mixed ingress. Optional per-target rules can override detection:

```dotenv
ZENTLOOP_PROXY_RULES=trap.example.com=cloudflare,*.internal.example.com=generic,203.0.113.25=direct
```

Only configure a trusted proxy mode when direct public access to the trap cannot bypass that proxy.

## Important environment variables

The repository contains `.env.example` with the complete deployment-oriented example. Common settings include:

| Variable | Default / Example | Purpose |
|---|---|---|
| `ZENTLOOP_ADMIN_USER` | `admin` | Web administrator username |
| `ZENTLOOP_ADMIN_PASSWORD` | empty | Optional stable web administrator password; if empty, a random password is printed at startup |
| `ZENTLOOP_PUBLIC_PORT` | `8080` | Host port for the HTTP trap |
| `ZENTLOOP_ADMIN_BIND` | `127.0.0.1` | Host bind address for web admin |
| `ZENTLOOP_ADMIN_PORT` | `9090` | Host port for web admin |
| `ZENTLOOP_PROXY_MODE` | `auto` | Visitor-IP attribution mode |
| `ZENTLOOP_MAX_CONCURRENT` | `256` | Global concurrency ceiling |
| `ZENTLOOP_RETENTION_DAYS` | `30` | Persistent event-log retention; values above 30 are hard-capped to 30 days |
| `ZENTLOOP_SSH_ENABLED` | `false` | Enable public SSH deception |
| `ZENTLOOP_SSH_PUBLIC_PORT` | `2222` | Bridge-host port for SSH deception |
| `ZENTLOOP_SSH_PROVIDER_ORG` | `AS16276 OVH SAS` | Synthetic provider/ASN organization returned by SSH provider discovery; set it to match the deployed target |
| `ZENTLOOP_ADMIN_SSH_ENABLED` | `false` | Enable management SSH TUI |
| `ZENTLOOP_ADMIN_SSH_BIND` | `127.0.0.1` | Host bind for management SSH |
| `ZENTLOOP_ADMIN_SSH_PORT` | `22222` | Host port for management SSH |
| `TZ` | `Europe/Berlin` | Container timezone |

## Data and backups

Persistent application data belongs in:

```text
/data
```

Depending on enabled features this can include event data, synthetic SSH state, generated ZentLoop host keys, GeoIP data and crawler-verification cache data.

Back up the persistent data volume before major updates. `events.jsonl`, `ssh-events.jsonl` and `intel-events.jsonl` are automatically compacted according to `ZENTLOOP_RETENTION_DAYS`. The default and hard maximum are 30 days; a configured value above 30 is still reduced to 30. Operators remain responsible for choosing a shorter retention period when required for their deployment.

Never mount real SSH keys, cloud credentials, production data, Docker sockets or sensitive host paths into the trap container.

## Updating

For Docker Compose:

```bash
docker compose pull
docker compose up -d
```

For Docker CLI:

```bash
docker pull ghcr.io/zentworks/zentloop:latest
```

Recreate the container with the same environment, ports and persistent data volume. Persistent `/data` content survives container replacement when the volume or host path is retained.

## Security

ZentLoop is intentionally exposed to untrusted traffic. Deployment isolation still matters.

- Keep administration interfaces private.
- Set a strong unique admin password for a stable credential, or securely record the generated startup password.
- Do not expose Docker sockets or sensitive host mounts.
- Do not reuse real host SSH keys as ZentLoop trap or management keys.
- Keep trap and management SSH host-key paths separate.
- Configure proxy trust only for the actual ingress topology.
- Configure `ZENTLOOP_RETENTION_DAYS` as appropriate; ZentLoop never retains the three persistent event logs beyond the 30-day hard cap by configuration.

See [SECURITY.md](SECURITY.md) for the detailed security model and boundaries.

## Scoring

Behavior scoring is documented in [docs/SCORING.md](docs/SCORING.md).

## License

ZentLoop is released under the [MIT License](LICENSE). You may use, modify, distribute and commercially use the software under the terms of the license. The copyright notice and MIT permission notice must be retained in copies or substantial portions of the software.
