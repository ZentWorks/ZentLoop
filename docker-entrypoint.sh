#!/bin/sh
set -eu

DATA_DIR="${ZENTLOOP_DATA_DIR:-/data}"
DB="${ZENTLOOP_GEOIP_DB:-${DATA_DIR}/dbip-country-lite.mmdb}"
AUTO="${ZENTLOOP_GEOIP_AUTO_UPDATE:-true}"

# Bind-mounted appdata may be created by the Docker host with ownership that the
# unprivileged ZentLoop user cannot write. Repair only the data directory and
# known runtime files, then immediately drop to the fixed runtime UID/GID.
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR"

  if ! su-exec zentloop:zentloop test -w "$DATA_DIR"; then
    chown zentloop:zentloop "$DATA_DIR"
    chmod u+rwx "$DATA_DIR"
  fi

  for path in \
    "$DATA_DIR/events.jsonl" \
    "$DATA_DIR/ssh-events.jsonl" \
    "$DATA_DIR/ssh-system.json" \
    "${ZENTLOOP_OFFICIAL_BOTS_CACHE:-${DATA_DIR}/official-bots.json}" \
    "$DB" \
    "${DB}.month" \
    "${ZENTLOOP_SSH_HOST_KEY_PATH:-${DATA_DIR}/ssh_trap_host_ed25519_key}" \
    "${ZENTLOOP_ADMIN_SSH_HOST_KEY_PATH:-${DATA_DIR}/ssh_host_ed25519_key}"; do
    if [ -e "$path" ] && ! su-exec zentloop:zentloop test -w "$path"; then
      chown zentloop:zentloop "$path"
      chmod u+rw "$path"
    fi
  done

  exec su-exec zentloop:zentloop /app/docker-entrypoint.sh "$@"
fi

case "$(printf '%s' "$AUTO" | tr '[:upper:]' '[:lower:]')" in
  1|true|yes|on)
    month="$(date -u +%Y-%m)"
    marker="${DB}.month"
    current=""
    [ -f "$marker" ] && current="$(cat "$marker" 2>/dev/null || true)"
    if [ ! -s "$DB" ] || [ "$current" != "$month" ]; then
      url="https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz"
      tmp="${DB}.gz.tmp"
      out="${DB}.tmp"
      mkdir -p "$(dirname "$DB")" 2>/dev/null || true
      if wget -q -T 20 -O "$tmp" "$url" && gzip -dc "$tmp" > "$out" && [ -s "$out" ]; then
        mv "$out" "$DB"
        printf '%s' "$month" > "$marker"
        echo "ZentLoop: GeoIP country database updated (${month})"
      else
        rm -f "$out"
        if [ ! -s "$DB" ]; then
          echo "ZentLoop: GeoIP database unavailable; country lookup will remain unknown for public direct/generic IPs" >&2
        else
          echo "ZentLoop: GeoIP update failed; keeping existing database" >&2
        fi
      fi
      rm -f "$tmp"
    fi
  ;;
esac

exec /app/zentloop "$@"
