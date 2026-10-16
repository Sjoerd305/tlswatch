#!/bin/sh
# Installs a tlswatch probe node. Served by @SERVER@ for one install token,
# which is valid for an hour and spent by this script. It changes nothing
# outside /var/lib/tlswatch-node, /usr/local/bin/tlswatch,
# /etc/tlswatch-node.env, /etc/systemd/system/tlswatch-node.service and
# the system user tlswatch-node. To read it before running it:
#   curl -fsSL @SERVER@/agent/v1/install/<token> | less
set -eu

SERVER=@SERVER_Q@
TOKEN=@TOKEN_Q@
ROOT="${TLSWATCH_INSTALL_ROOT:-}" # for the tests only; empty installs into /
DATA=/var/lib/tlswatch-node
ENVFILE=/etc/tlswatch-node.env
UNIT=/etc/systemd/system/tlswatch-node.service
NODE_USER=tlswatch-node

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\ntlswatch: %s\n' "$*" >&2; exit 1; }
untrusted() {
	die "this machine does not trust the certificate of $SERVER. A server on a private CA needs that CA in the trust store of this host (on Debian and Ubuntu: copy it to /usr/local/share/ca-certificates and run update-ca-certificates), then run the command again."
}

step "Checking this machine"
[ "$(id -u)" = 0 ] || die "this must run as root. Put sudo before sh, not before curl:

    curl -fsSL $SERVER/agent/v1/install/$TOKEN | sudo sh
"
if command -v curl >/dev/null 2>&1; then
	FETCH=curl
elif command -v wget >/dev/null 2>&1; then
	FETCH=wget
else
	die "curl or wget is needed"
fi
command -v systemctl >/dev/null 2>&1 || die "systemd is needed; use the Docker or manual command from the Add node screen instead"
case "$(uname -s)" in
Linux) OS=linux ;;
*) die "this script installs on Linux; use the manual command from the Add node screen on $(uname -s)" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7l) ARCH=arm ;;
armv6l) die "tlswatch nodes need ARMv7 or newer; this machine is $(uname -m)" ;;
*) die "tlswatch nodes run on amd64, arm64 and armv7, not on $(uname -m)" ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
	SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	SHA="shasum -a 256"
else
	die "sha256sum is needed to verify the download"
fi
echo "Linux $ARCH with $FETCH and systemd"

step "Downloading tlswatch for $OS/$ARCH from $SERVER"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL="$SERVER/agent/v1/download/$OS/$ARCH?token=$TOKEN"
status=0
if [ "$FETCH" = curl ]; then
	curl -fsSL -D "$TMP/headers" -o "$TMP/tlswatch" "$URL" || status=$?
	[ "$status" != 60 ] || untrusted
else
	wget -q -S -O "$TMP/tlswatch" "$URL" 2>"$TMP/headers" || status=$?
	[ "$status" != 5 ] || untrusted
fi
[ "$status" = 0 ] || die "the download failed ($FETCH exit status $status). A platform other than the server's own is fetched from GitHub, which this machine must then reach."
WANT=$(tr -d '\r' <"$TMP/headers" | awk 'tolower($1) == "x-tlswatch-sha256:" { print tolower($2) }' | head -n 1)
[ -n "$WANT" ] || die "the server sent no checksum with the binary"
GOT=$($SHA "$TMP/tlswatch" | awk '{ print $1 }')
[ "$GOT" = "$WANT" ] || die "the download is corrupt: SHA-256 $GOT, expected $WANT"
echo "SHA-256 $GOT verified"

step "Installing into $DATA"
if ! id "$NODE_USER" >/dev/null 2>&1; then
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --user-group --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$NODE_USER"
	else
		adduser --system --group --home "$DATA" --no-create-home --shell /usr/sbin/nologin "$NODE_USER"
	fi
	echo "created the system user $NODE_USER"
fi
if systemctl is-active --quiet tlswatch-node.service 2>/dev/null; then
	systemctl stop tlswatch-node.service
	echo "stopped the running node"
fi
mkdir -p "$ROOT$DATA/bin" "$ROOT/usr/local/bin" "$ROOT/etc/systemd/system"
chmod 0700 "$ROOT$DATA"
# The binary belongs to the node's user, so the node can update itself.
install -m 0755 "$TMP/tlswatch" "$ROOT$DATA/bin/tlswatch"
rm -f "$ROOT$DATA/bin/tlswatch.prev" "$ROOT$DATA/update.json" "$ROOT$DATA/update-failed.json"
ln -sf "$DATA/bin/tlswatch" "$ROOT/usr/local/bin/tlswatch"
umask 022
cat >"$ROOT$ENVFILE" <<EOF
# tlswatch node, written by the install script from $SERVER
TLSWATCH_NODE_SERVER=$SERVER
TLSWATCH_NODE_DATA=$DATA
# The node replaces its binary only with a release signed by the tlswatch
# release key. TLSWATCH_NODE_NO_UPDATE=true keeps it on this binary;
# TLSWATCH_NODE_ALLOW_UNSIGNED_UPDATE=true also follows development builds.
EOF
echo "$DATA/bin/tlswatch, linked from /usr/local/bin/tlswatch; settings in $ENVFILE"

step "Enrolling with $SERVER"
"$ROOT$DATA/bin/tlswatch" node enrol -server "$SERVER" -token "$TOKEN" -data "$ROOT$DATA"
chown -R "$NODE_USER:$(id -gn "$NODE_USER")" "$ROOT$DATA"

step "Starting the service tlswatch-node"
cat >"$ROOT$UNIT" <<EOF
[Unit]
Description=tlswatch probe node
Documentation=$SERVER/settings/nodes
After=network-online.target
Wants=network-online.target

[Service]
User=$NODE_USER
EnvironmentFile=$ENVFILE
ExecStart=$DATA/bin/tlswatch node
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tlswatch-node.service
systemctl restart tlswatch-node.service

echo
echo "Connected to $SERVER as $(hostname); finish in the UI."
