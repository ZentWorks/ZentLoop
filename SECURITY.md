# Security model

ZentLoop is designed to receive untrusted Internet traffic. Treat every public trap listener as hostile-facing infrastructure.

## Deployment rules

- Isolate ZentLoop from production networks where practical.
- Never mount the Docker socket, real SSH keys, cloud credentials, production data or sensitive host paths.
- Keep the web admin private. The generic Compose profile binds it to `127.0.0.1:9090` on the Docker host.
- Use a VPN or authenticated TLS reverse proxy for remote web administration.
- Set a strong unique admin password when a stable credential is desired. If `ZENTLOOP_ADMIN_PASSWORD` is empty, ZentLoop generates a random password at startup and prints it once to the container log; it changes again on the next restart unless explicitly configured.
- The Web Admin login creates an in-memory 12-hour session with an HttpOnly SameSite=Strict cookie (Secure on HTTPS). Write actions require a per-session CSRF token. Logout invalidates the server-side session immediately; sessions also disappear on ZentLoop restart.
- Select `ZENTLOOP_PROXY_MODE=cloudflare` only for a Cloudflare-proxied hostname or Cloudflare Tunnel. ZentLoop then trusts `CF-Connecting-IP` for visitor attribution.
- Select `ZENTLOOP_PROXY_MODE=generic` only when direct access to the HTTP trap is blocked and your trusted reverse proxy is the only ingress path. Generic mode trusts forwarded-IP headers.
- Keep `ZENTLOOP_PROXY_MODE=direct` for direct-IP HTTP deployments.

## Public SSH deception boundary

The optional `ZENTLOOP_SSH_ENABLED` listener is a deception service, not an operating-system login.

- It must use its own generated host key (`ZENTLOOP_SSH_HOST_KEY_PATH`, default `/data/ssh_trap_host_ed25519_key`).
- Attacker commands are parsed only by ZentLoop's virtual shell. They are never passed to `/bin/sh`, real `bash`, `exec.Command`, Docker or another process runner.
- Readline-style history/editing, shell operators/pipes/redirects, environment variables, `bash -c`, sourced virtual scripts, interpreter probes and editor `:!` commands all remain inside the same bounded simulator.
- Interactive `vim`/`vi`, `nano` and `top` render only to the attacker's SSH TTY and read/write only session-local virtual state. They do not launch host programs or open real files.
- The attacker-visible virtual filesystem is an in-memory map containing synthetic data. It cannot expose `/data`, `/etc`, application files or other paths from the real container filesystem. The only SSH decoy state persisted by the server itself outside event logs is the fixed-path `/data/ssh-system.json` synthetic boot/seed record; attacker commands cannot choose or read that host path.
- Simulated `curl`, `wget`, `ssh`, `scp`, `ping`, `nc` and related behavior never opens an attacker-directed outbound connection. Content-aware download bodies, headers, sizes and file metadata are generated locally.
- TCP/remote forwarding, agent forwarding, X11 and SFTP/subsystems are rejected.
- Global concurrent sessions, per-IP sessions, authentication attempts, idle time, total session time, input length and stored output are bounded.
- Clearly aggressive repeat SSH sources may receive a small adaptive banner delay. The delay is capped at three seconds, uses a separate maximum-eight-slot semaphore and is skipped when that budget is occupied; it does not change authentication acceptance or the 60-second human-pacing auth timeout.
- SSH passwords are not persisted. Authentication logs retain password-presence/length metadata only.
- Attacker-controlled strings are sanitized before terminal/TUI rendering to remove terminal control/escape sequences.

On a normal bridge-network Docker host, do not steal the host's real TCP/22 accidentally; the example Compose file maps the trap to host TCP/2222 by default. With a dedicated ZentLoop IP, the trap can instead use TCP/22 on that dedicated address.

## Adaptive deception and synthetic internal network

Adaptive SSH clues and the shared HTTP/SSH internal topology are data-only simulations. Discovering a fake database, registry, backup host, Git server or operations gateway never creates a connection to such a service. Nested SSH, DNS, ping, netcat, registry access and downloader behavior resolve only inside ZentLoop's virtual model. Decoy tokens are never used for authentication outside that model.

## Management SSH boundary

Management SSH is separate from the public trap and defaults to TCP/22222. Keep it on a trusted LAN/VPN. It uses public-key authentication and only renders the existing ZentLoop live TUI; it provides no system shell, exec commands, SCP/SFTP, agent forwarding or TCP forwarding.

Management SSH and the public trap must use different host-key paths. ZentLoop validates this when both are enabled. Never substitute a real machine/server private key for either generated ZentLoop host key.

## Passive-only principle

ZentLoop may delay or alter responses served by ZentLoop itself. It must not scan, exploit, send malware to, connect back to, or otherwise attack a visitor.

## Data

HTTP events record source IP addresses, request paths, methods, user agents and derived behavior scores. HTTP request bodies and cookies are not persisted by the MVP. SSH events record source IP/country, client banner, username, authentication metadata, virtual commands/results and derived behavior. Raw SSH passwords are not persisted. `/data/intel-events.jsonl` contains only passive remote-resource indicators and decoy-token reuse metadata; common password/token/secret/OTP form fields are excluded before HTTP indicator extraction. `/data/ssh-system.json` contains synthetic decoy boot/seed state only and no attacker credentials or host telemetry.

Cross-protocol actor correlation uses the observed source IP as a correlation key. Treat it as operational attribution, not proof of a person: NAT, reverse proxies and address rotation can affect the mapping. Deterministic decoy tokens are synthetic values derived only for deception/correlation and must never be accepted by a real service.

The Admin IP Intelligence view and its JSON export expose only data ZentLoop already retains for that observed source. Possible campaign peers are heuristic correlations derived from timing, fingerprints, SSH client families, username overlap and revisit cadence; confidence scores are not identity attribution. Keep exports protected like the Admin interface because they can contain source IPs, requested paths, usernames, virtual commands and passive indicators.

Persistent `events.jsonl`, `ssh-events.jsonl` and `intel-events.jsonl` use `ZENTLOOP_RETENTION_DAYS` with a default of 30 days and a hard 30-day maximum. Values above 30 are clamped to 30. ZentLoop compacts these logs at startup and periodically while running. Critical aggregate storage pressure also triggers bounded tail compaction that preserves the newest complete JSONL records instead of allowing retained event files to grow indefinitely. Operators remain responsible for selecting any shorter retention period and for meeting the legal/privacy requirements that apply to their own deployment.

## Reverse-proxy integration headers

`X-ZentLoop-*` integration metadata is never trusted from an arbitrary public client. With no integration secret configured, metadata is accepted only when the immediate TCP peer is private/loopback. If `ZENTLOOP_INTEGRATION_SECRET` is set, a valid timestamped HMAC-SHA256 signature is required even for private peers. Multiple accepted secrets may be configured as one quoted comma-separated value such as `"eins,zwe!,dr3i"`; commas delimit secrets. Use catch-all routing only for unmatched hosts; do not send application failures or known production hosts to ZentLoop.


### Official crawler verification

Official-bot refresh traffic is intentionally constrained to a compiled-in list of provider HTTPS endpoints. No visitor-controlled host, URL, header or path can influence the destination. The cache is advisory classification data only. A failed/partial provider refresh never converts an unknown claim into a spoof verdict merely because the new feed was unavailable.

The authenticated Admin UI also has a fixed-destination update check for the public `ZentWorks/ZentLoop` GitHub latest stable release. It is started asynchronously after admin login/first Admin info load, cached for 12 hours, and uses a short timeout. The request contains only the normal GitHub API request metadata and a ZentLoop version User-Agent; it does not include installation IDs, source IP intelligence, sessions, events, credentials or other collected traffic. Failure is fail-closed for the badge and cannot affect trap operation. No automatic update mechanism exists.

The low-and-slow SSH deception policy may occasionally accept a recurring synthetic login attempt into the virtual Rabbit Hole. It does not retain passwords, does not compare them with any real system credential, and does not change the fundamental no-real-shell/no-outbound-network boundary.


## SSH anti-fingerprint surface (0.2.5)

The Deep Reality layer is a deterministic in-process simulation. `/proc`, `/sys`, DMI, TTY and virtualization responses are synthesized from ZentLoop's virtual state. Visitor input is never passed to `/bin/sh`, `bash`, `systemd-detect-virt`, `dmidecode`, `stty`, `cat`, or any other host executable. The feature does not add visitor-controlled filesystem paths or outbound network destinations.

## Integration health verification (0.2.6)

The public trap recognizes `/.well-known/zentloop/integration-check`, but only successfully trusted integration metadata can bypass normal deception logging. A valid check is handled before session/actor creation and returns only HTTP 204 plus `X-ZentLoop-Integration-Verified: 1`. Invalid claimed checks remain logged and receive HTTP 403; unclaimed probes receive a neutral logged 404.

Integration peer state never stores or exposes `ZENTLOOP_INTEGRATION_SECRET` or request signatures. Peer persistence contains only provider name, immediate peer IP, trust/status timestamps, aggregate counters and an opaque matched configuration slot such as `key-2`; the slot is positional and is not a hash/fingerprint of the secret.

## Scanner-fed SSRF and file-read deception (0.2.7)

ZentLoop's HTTP fetch/proxy/preview/webhook and `/@fs` responses are simulator-only. Attacker-controlled URLs are parsed for deception context but are never fetched, resolved or dialed by the lure engine. File-read probes are mapped only onto synthetic content; request paths cannot select real files from the ZentLoop container or host. Cloud, Terraform and SQL credential material returned by these families is deterministic decoy data and may contain ZentLoop canary values, never real credentials.

## Virtual background processes

SSH background jobs introduced in 0.2.8 are metadata-only simulation objects. `&`, `jobs`, `disown`, `pkill`, `killall`, `chmod` and staged payload execution never invoke host processes or attacker-provided binaries. Temporary paths, `/dev/null`, process state, crontabs, attributes and history are maintained only inside the per-session virtual SSH world.


## SSH observability and exports

SSH live observability reuses retained SSH events and, since 0.2.15, the single authenticated same-origin Admin WebSocket shared with HTTP live deltas. Since 0.2.20 the WebSocket is authenticated by the same browser Admin session; same-origin validation remains mandatory. The fixed 60-second recently-left window is presentation metadata only. JSON/TXT exports are available only through the authenticated admin interface and contain only data ZentLoop already retains; plaintext passwords are not added to events or exports.


## 0.2.10 scanner-fed protocol handling

ActivityPub `/inbox` traffic is classified benign only when method and protocol evidence match federation delivery; the path alone never suppresses security visibility. New WordPress/PHP, key/config and SSH collector lures remain fully synthetic. The virtual GPU/coreutils changes do not execute host commands or access host devices.


## 0.2.11 bounded exec-stdin staging

SSH exec stdin is read only for commands that intentionally consume it and is capped by the virtual-file byte budget. Captured bytes are passed only to the in-memory virtual shell/filesystem. ZentLoop never executes them, never writes them into the host/container filesystem and never opens a network connection because of their content. Persisted SSH event metadata contains only bounded byte count, SHA-256 and coarse content type; plaintext exec-stdin payload bytes are not added to the event log. Shell control-flow support is a parser/simulator subset and never delegates to `/bin/sh`, Bash or another interpreter.
