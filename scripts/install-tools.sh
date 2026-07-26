#!/bin/sh
# =============================================================================
# install-tools.sh — bootstrap the security tools Dark-Recon drives.
# =============================================================================
# Thin wrapper around the prerequisites engine (scripts/check-prereqs.sh).
# Keeping a single source of truth means the CLI, the web UI and the .deb
# launcher can never disagree on what is required or how it is installed.
#
# It auto-installs:
#   • REQUIRED Go tools   via `go install`   (subfinder, ffuf, httpx,
#                          webanalyze, katana, nuclei, subzy)
#   • OPTIONAL tools      when --strict      (nmap/apt, naabu, chaos,
#                          trufflehog, gitleaks, wafw00f, arjun, seclists)
#   • nuclei templates    if nuclei is present
#
# Run:  bash scripts/install-tools.sh [--strict] [--no-sudo]
# Env:  GOBIN / GOPATH respected; defaults to ~/go/bin (or /usr/local/bin as root).
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
ENGINE="$SCRIPT_DIR/check-prereqs.sh"

# Legacy compat: --no-sudo is accepted but mapped to skipping apt installs by
# letting the engine run; the engine itself skips apt when sudo is unavailable.
STRICT=""
for _a in "$@"; do
	case "$_a" in
		--strict)  STRICT="--strict" ;;
		--no-sudo) ;;  # acknowledged; engine skips apt without sudo
		*) ;;
	esac
done

if [ ! -x "$ENGINE" ] && [ ! -f "$ENGINE" ]; then
	echo "ERROR: prerequisites engine not found at: $ENGINE" >&2
	exit 1
fi

# GOBIN default mirrors the engine (root -> /usr/local/bin, else ~/go/bin).
if [ -z "${GOBIN:-}" ]; then
	if [ "$(id -u)" -eq 0 ]; then
		GOBIN="/usr/local/bin"
	else
		GOBIN="${HOME}/go/bin"
	fi
fi
export GOBIN
mkdir -p "$GOBIN" 2>/dev/null || true
export PATH="$GOBIN:$PATH"

echo "==> Installing missing tools (GOBIN=$GOBIN)"
sh "$ENGINE" --install $STRICT
_rc=$?

case "$_rc" in
	0) echo "==> Done. Verify with: bash scripts/check-prereqs.sh" ;;
	1) echo "==> Some REQUIRED tools could not be installed (see report above)." >&2 ;;
	2) echo "==> Required tools installed; some optional items still missing." ;;
esac
echo "    Ensure $GOBIN is on your PATH:"
echo "      export PATH=\"\$PATH:$GOBIN\""
exit "$_rc"
