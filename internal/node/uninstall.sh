#!/bin/sh
# Removes a tlswatch probe node installed by the install script. Served by
# @SERVER@; it needs no token and works when the node's binary is missing
# or broken. It removes /etc/systemd/system/tlswatch-node.service,
# /etc/tlswatch-node.env, /usr/local/bin/tlswatch (only when it points into
# /var/lib/tlswatch-node), /var/lib/tlswatch-node with the credential, and
# the system user tlswatch-node; nothing else. To read it first:
#   curl -fsSL @SERVER@/agent/v1/uninstall | less
set -eu

ROOT="${TLSWATCH_INSTALL_ROOT:-}" # for the tests only; empty removes from /
DATA=/var/lib/tlswatch-node
ENVFILE=/etc/tlswatch-node.env
UNIT=/etc/systemd/system/tlswatch-node.service
LINK=/usr/local/bin/tlswatch
NODE_USER=tlswatch-node

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\ntlswatch: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "this must run as root. Put sudo before sh, not before curl:

    curl -fsSL @SERVER@/agent/v1/uninstall | sudo sh
"

step "Stopping the service tlswatch-node"
if command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now tlswatch-node.service 2>/dev/null || true
fi
for f in "$UNIT" "$ENVFILE"; do
	if [ -e "$ROOT$f" ]; then
		rm -f "$ROOT$f"
		echo "removed $f"
	fi
done
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload 2>/dev/null || true
fi

step "Removing the files"
if [ -L "$ROOT$LINK" ]; then
	case "$(readlink "$ROOT$LINK")" in
	"$DATA"/*)
		rm -f "$ROOT$LINK"
		echo "removed $LINK"
		;;
	esac
fi
if [ -d "$ROOT$DATA" ]; then
	rm -rf "$ROOT$DATA"
	echo "removed $DATA"
fi

step "Removing the user $NODE_USER"
if id "$NODE_USER" >/dev/null 2>&1; then
	if command -v userdel >/dev/null 2>&1; then
		userdel "$NODE_USER"
	else
		deluser "$NODE_USER"
	fi
	echo "removed the user $NODE_USER"
else
	echo "no such user"
fi

echo
echo "The node is removed from $(hostname). Delete it in tlswatch under Settings › Nodes: @SERVER@/settings/nodes"
