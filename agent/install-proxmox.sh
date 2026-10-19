#!/usr/bin/env bash
# Sentinel agent installer for Proxmox (Debian-based host).
#
# Copies the agent into /opt/sentinel, installs Node.js (and nmap if you
# choose the nmap scanner), and sets up a systemd service + timer that runs
# every 5 minutes.
#
# Usage (as root, from the folder that contains this script AND the agent):
#   sudo ./install-proxmox.sh
# or non-interactively:
#   sudo SENTINEL_URL=... SENTINEL_TOKEN=... SCAN_SUBNETS=192.168.1.0/24 SCANNER=nmap ./install-proxmox.sh
#
# Re-running is safe: it updates the files and restarts the timer.

set -euo pipefail

APP_DIR=/opt/sentinel
ENV_FILE=/etc/sentinel-agent.env
SERVICE=/etc/systemd/system/sentinel-agent.service
TIMER=/etc/systemd/system/sentinel-agent.timer
SERVICE_USER=sentinel

if [[ $EUID -ne 0 ]]; then
	echo "Kør som root: sudo $0" >&2
	exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"
for f in sentinel-agent.mjs nmap-xml.mjs; do
	if [[ ! -f "$here/$f" ]]; then
		echo "Kunne ikke finde $here/$f. Kør scriptet fra mappen med agent-filerne." >&2
		exit 1
	fi
done

# ---- gather configuration -------------------------------------------------

detect_subnet() {
	local dev ip
	dev="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
	[[ -z "$dev" ]] && return 0
	ip="$(ip -4 -o addr show dev "$dev" | awk '{print $4}' | cut -d/ -f1 | head -1)"
	[[ -z "$ip" ]] && return 0
	echo "${ip%.*}.0/24"
}

SENTINEL_URL="${SENTINEL_URL:-}"
SENTINEL_TOKEN="${SENTINEL_TOKEN:-}"
SCAN_SUBNETS="${SCAN_SUBNETS:-$(detect_subnet)}"
SCANNER="${SCANNER:-}"
ENABLE_PORT_SCAN="${ENABLE_PORT_SCAN:-false}"
SERVICE_DETECTION="${SERVICE_DETECTION:-false}"
INTERVAL_MINUTES="${INTERVAL_MINUTES:-15}"
ENABLE_VULN_SCAN="${ENABLE_VULN_SCAN:-true}"
VULN_SCAN_TIME="${VULN_SCAN_TIME:-12:00}"

if [[ -z "$SENTINEL_URL" ]]; then read -rp "SENTINEL_URL: " SENTINEL_URL; fi
if [[ -z "$SENTINEL_TOKEN" ]]; then read -rsp "SENTINEL_TOKEN: " SENTINEL_TOKEN; echo; fi
if [[ -z "$SCAN_SUBNETS" ]]; then read -rp "SCAN_SUBNETS (fx 192.168.1.0/24): " SCAN_SUBNETS; fi
if [[ -z "$SCANNER" ]]; then
	read -rp "SCANNER [simple/nmap] (simple): " _s
	SCANNER="${_s:-simple}"
fi

# ---- install dependencies --------------------------------------------------

if ! command -v node >/dev/null 2>&1; then
	echo "Installerer Node.js ..."
	apt-get update -qq
	apt-get install -y -qq nodejs
fi
echo "Node: $(node --version)"

if [[ "$SCANNER" == "nmap" || "$ENABLE_VULN_SCAN" == "true" ]] && ! command -v nmap >/dev/null 2>&1; then
	echo "Installerer nmap ..."
	apt-get update -qq
	apt-get install -y -qq nmap
fi
if ! command -v ping >/dev/null 2>&1; then
	apt-get update -qq && apt-get install -y -qq iputils-ping || true
fi

# ---- install the agent -----------------------------------------------------

id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -m 0755 "$APP_DIR"
install -m 0755 "$here/sentinel-agent.mjs" "$APP_DIR/sentinel-agent.mjs"
install -m 0644 "$here/nmap-xml.mjs" "$APP_DIR/nmap-xml.mjs"

umask 077
cat > "$ENV_FILE" <<EOF
SENTINEL_URL=$SENTINEL_URL
SENTINEL_TOKEN=$SENTINEL_TOKEN
SCAN_SUBNETS=$SCAN_SUBNETS
SCANNER=$SCANNER
ENABLE_PORT_SCAN=$ENABLE_PORT_SCAN
SERVICE_DETECTION=$SERVICE_DETECTION
EOF
chmod 600 "$ENV_FILE"

# ---- systemd ---------------------------------------------------------------

cat > "$SERVICE" <<EOF
[Unit]
Description=Sentinel network agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
ExecStart=$(command -v node) $APP_DIR/sentinel-agent.mjs
EOF

cat > "$TIMER" <<EOF
[Unit]
Description=Run Sentinel agent every $INTERVAL_MINUTES minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL_MINUTES}min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

if [[ "$ENABLE_VULN_SCAN" == "true" ]]; then
	cat > /etc/systemd/system/sentinel-agent-vuln.service <<EOF
[Unit]
Description=Sentinel vulnerability scan (nmap --script vuln)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
Environment=MODE=vuln
ExecStart=$(command -v node) $APP_DIR/sentinel-agent.mjs
EOF

	cat > /etc/systemd/system/sentinel-agent-vuln.timer <<EOF
[Unit]
Description=Daily Sentinel vulnerability scan

[Timer]
OnCalendar=*-*-* ${VULN_SCAN_TIME}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
fi

systemctl daemon-reload
systemctl enable --now sentinel-agent.timer
if [[ "$ENABLE_VULN_SCAN" == "true" ]]; then
	systemctl enable --now sentinel-agent-vuln.timer
fi

# ---- first run -------------------------------------------------------------

echo
echo "Kører et første scan nu (dry-run for at vise hvad der findes) ..."
sudo -u "$SERVICE_USER" env $(grep -v '^#' "$ENV_FILE" | xargs) \
	node "$APP_DIR/sentinel-agent.mjs" --dry-run || true

echo
echo "Færdig."
echo "  Status:  systemctl status sentinel-agent.timer"
echo "  Logs:    journalctl -u sentinel-agent -n 50 --no-pager"
echo "  Subnet:  $SCAN_SUBNETS"
echo "  Scanner: $SCANNER"
echo "  Interval: hver $INTERVAL_MINUTES. minut"
echo "  Daglig sårbarhedsscan: $ENABLE_VULN_SCAN kl. $VULN_SCAN_TIME"
echo
echo "Tjek Enheder-siden i Sentinel om lidt for at se resultatet."
