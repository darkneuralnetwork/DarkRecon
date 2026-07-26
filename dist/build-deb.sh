#!/usr/bin/env bash
# =============================================================================
# build-deb.sh - Build the Dark-Recon .deb package
# =============================================================================
# Produces: dist/dark-recon_<version>_<arch>.deb
#
# Design goals (the package MUST install on a clean/minimal Debian/Ubuntu):
#   * Minimal hard Depends (only libc6, which is always present) so that
#     `dpkg -i` never aborts with "dependency problems - leaving unconfigured".
#     Everything else is a Recommends (apt pulls it by default, but it cannot
#     block installation).
#   * Statically-linked Go binary (CGO_ENABLED=0) -> runs on ANY linux/amd64
#     regardless of the host glibc version. modernc.org/sqlite is pure-Go.
#   * postinst is bulletproof and ALWAYS exits 0. By default it runs a FAST,
#     read-only prerequisites VERIFICATION (no network) for immediate feedback;
#     a full network INSTALL at install time is opt-in via
#     DARK_RECON_INSTALL_PREREQS=1. Otherwise the heavy Go tool installs are
#     deferred to first launch via the bundled prerequisites engine.
#   * Bundles every runtime file (binary, configs, wordlists,
#     UI templates/static, README) + the prerequisites engine
#     (scripts/check-prereqs.sh) + installer wrapper (scripts/install-tools.sh).
#   * The /usr/local/bin/dark-recon launcher runs the prerequisites engine on
#     first launch, AUTO-INSTALLING missing required (Go) tools, and exposes a
#     `dark-recon prereqs` subcommand for explicit checks.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Version: explicit $VERSION > git tag (strip leading 'v') > 1.0.0 fallback.
# In CI (tag push) this yields the release version; locally it falls back.
if [ -z "${VERSION:-}" ]; then
	_git_ver="$(git describe --tags --always 2>/dev/null | sed 's/^v//' || true)"
	VERSION="${_git_ver:-1.0.0}"
fi
# Architecture: explicit $TARGET_ARCH (for cross-builds, e.g. arm64 on an
# amd64 runner) > host dpkg architecture.
ARCH="${TARGET_ARCH:-$(dpkg --print-architecture)}"
PKG="dark-recon"
STAGING="dist/staging"
INST_PREFIX="usr/share/${PKG}"
DEB="dist/${PKG}_${VERSION}_${ARCH}.deb"

echo "==> Cleaning previous build"
rm -rf "$STAGING" "$DEB"
mkdir -p "$STAGING/DEBIAN" "$STAGING/${INST_PREFIX}" "$STAGING/usr/local/bin" \
         "$STAGING/${INST_PREFIX}/scripts"

APPDIR="$STAGING/${INST_PREFIX}"

echo "==> Building STATIC Go binary (CGO_ENABLED=0, GOOS=linux GOARCH=$ARCH, no glibc dependency)"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags="-s -w" -o "$APPDIR/dark-recon" ./cmd/dark-recon/
chmod 0755 "$APPDIR/dark-recon"
# Sanity: confirm it is statically linked.
if command -v file >/dev/null 2>&1; then
    if file "$APPDIR/dark-recon" | grep -q "statically linked"; then
        echo "    OK: binary is statically linked"
    else
        echo "    WARNING: binary is NOT static - it may not run on older systems"
    fi
fi

echo "==> Staging runtime files"
cp -a dark_recon        "$APPDIR/"
cp -a wordlists            "$APPDIR/"
cp -a configs              "$APPDIR/" 2>/dev/null || true
cp -a config.yaml          "$APPDIR/"
cp -a tools_config.yaml    "$APPDIR/"
# Ship a SANITIZED llm_config.yaml so a developer's local API keys are never
# baked into the package. The end user edits it (or the Settings UI) post-install.
cat > "$APPDIR/llm_config.yaml" <<'EOF'
enabled: false
provider: ollama
model: llama3
api_key: ''
base_url: http://localhost:11434
onboarded: false
EOF
cp -a README.md            "$APPDIR/"
cp -a go.mod go.sum        "$APPDIR/" 2>/dev/null || true
# Go source for reference / rebuilds
mkdir -p "$APPDIR/src"
cp -a cmd internal pkg     "$APPDIR/src/" 2>/dev/null || true
# Strip editor cruft.
find "$APPDIR" -type f -name '*.swp' -delete 2>/dev/null || true

echo "==> Staging prerequisites engine + installer (single source of truth)"
# The engine is the canonical prerequisites checker/installer, kept in sync
# with internal/installer/installer.go. The launcher wrapper calls it on first
# run; install-tools.sh is a thin wrapper around it for explicit `make` use.
cp -a scripts/check-prereqs.sh "$APPDIR/scripts/"
cp -a scripts/install-tools.sh "$APPDIR/scripts/"
chmod 0755 "$APPDIR/scripts/check-prereqs.sh" "$APPDIR/scripts/install-tools.sh"

echo "==> Staging launcher wrapper (auto prerequisites check on first run)"
cat > "$STAGING/usr/local/bin/dark-recon" <<'EOF'
#!/bin/sh
# Dark-Recon launcher (/usr/local/bin/dark-recon).
#   * Resolves config/templates relative to the install dir.
#   * On first run (or when forced) it runs the bundled prerequisites engine,
#     which checks the system + every security tool Dark-Recon drives and
#     AUTO-INSTALLS the missing REQUIRED ones (core pipeline = `go install`,
#     no sudo needed). Optional tools are reported, not installed.
#
# Subcommands:
#   dark-recon prereqs [--install] [--strict]   run the prerequisites engine
#   dark-recon ...                              launch the web server
#
# Environment:
#   DARK_RECON_SKIP_PREREQS=1     skip the first-run check entirely
#   DARK_RECON_FORCE_PREREQS=1    re-run the check even if already verified
APP_DIR=/usr/share/dark-recon
STATE_DIR=/var/lib/dark-recon
MARKER_SYS="$STATE_DIR/.prereqs-ok"
MARKER_USER="${XDG_CACHE_HOME:-$HOME/.cache}/dark-recon/.prereqs-ok"
ENGINE="$APP_DIR/scripts/check-prereqs.sh"

# A previous successful check wrote either the system marker (root) or the
# per-user marker (non-root). Either counts as "verified".
marker_present() { [ -f "$MARKER_SYS" ] || [ -f "$MARKER_USER" ]; }
write_marker() {
    # Try the system marker (root install); fall back to a per-user marker.
    # NB: test writability FIRST. A failed redirection prints a shell error
    # that `2>/dev/null` on the *same* command does NOT suppress, because the
    # error occurs during redirect setup (before the command runs). Using
    # `[ -w ]` first means we never attempt the open for a dir we can't write.
    if [ -d "$STATE_DIR" ] && [ -w "$STATE_DIR" ]; then
        : > "$MARKER_SYS" 2>/dev/null && return 0
    fi
    _user_dir="$(dirname "$MARKER_USER")"
    mkdir -p "$_user_dir" 2>/dev/null || true
    if [ -d "$_user_dir" ] && [ -w "$_user_dir" ]; then
        : > "$MARKER_USER" 2>/dev/null || true
    fi
    return 0
}

# -- `dark-recon prereqs [...]` : explicit prerequisites subcommand -----------
if [ "${1:-}" = "prereqs" ]; then
    shift
    if [ -f "$ENGINE" ]; then
        exec sh "$ENGINE" "$@"
    fi
    echo "prerequisites engine not found at $ENGINE" >&2
    exit 1
fi

# -- First-run prerequisites gate ---------------------------------------------
# Fast path: once verified, normal launches skip the check. Force a recheck
# with DARK_RECON_FORCE_PREREQS=1 or by removing the marker:
#   sudo rm -f /var/lib/dark-recon/.prereqs-ok
if [ "${DARK_RECON_SKIP_PREREQS:-0}" != "1" ]; then
    if [ "${DARK_RECON_FORCE_PREREQS:-0}" = "1" ] || ! marker_present; then
        if [ -f "$ENGINE" ]; then
            echo "> Dark-Recon: checking prerequisites (first run)..."
            # --install auto-installs missing REQUIRED (Go) tools; the core
            # pipeline needs no sudo. Optional tools are only reported.
            if sh "$ENGINE" --install; then
                write_marker
                echo "> Prerequisites OK."
                echo "  (skip on next launch: export DARK_RECON_SKIP_PREREQS=1)"
            else
                echo "! Some required tools are missing and could not be auto-installed." >&2
                echo "  The server will still start, but scans may fail. Fix with:" >&2
                echo "    sudo $ENGINE --install --strict" >&2
            fi
            echo
        fi
    fi
fi

cd "$APP_DIR" 2>/dev/null || true

# Copy default config to user's ~/.config directory so it can be edited/saved
USER_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/dark-recon/config.yaml"
if [ ! -f "$USER_CONFIG" ]; then
    mkdir -p "$(dirname "$USER_CONFIG")" 2>/dev/null || true
    cp "$APP_DIR/config.yaml" "$USER_CONFIG" 2>/dev/null || true
fi

exec "$APP_DIR/dark-recon" -config "$USER_CONFIG" "$@"
EOF
chmod 0755 "$STAGING/usr/local/bin/dark-recon"

echo "==> Writing Debian control metadata"
INSTALLED_KB="$(du -sk "$STAGING/${INST_PREFIX}" | cut -f1)"
cat > "$STAGING/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Dark-Recon <noreply@dark-recon.local>
Installed-Size: ${INSTALLED_KB}
Section: net
Priority: optional
Depends: libc6
Recommends: nmap, git, ca-certificates, golang-go, seclists
Description: Automated cybersecurity reconnaissance platform (Phase 1 recon engine)
 Dark-Recon orchestrates a multi-phase reconnaissance pipeline that
 discovers subdomains, detects live hosts, fingerprints technologies,
 crawls web applications, scans for vulnerabilities, checks for subdomain
 takeover, and ranks targets by attack priority - through a web-based UI
 with real-time WebSocket progress streaming.
 .
 This single package bundles the static, self-contained Go server binary
 (web UI embedded), default configuration, wordlists, UI templates/static
 assets, and a prerequisites engine. At install time postinst runs a fast
 read-only prerequisites VERIFICATION; on first launch the launcher checks
 the system and AUTO-INSTALLS the missing required Go security tools
 (subfinder, ffuf, httpx, webanalyze, katana, nuclei, subzy). A full
 bootstrap at install time is opt-in: DARK_RECON_INSTALL_PREREQS=1.
 Optional tooling (nmap, seclists, ...) is declared as Recommends and can
 also be installed via:
   dark-recon prereqs --install --strict
   sudo /usr/share/dark-recon/scripts/install-tools.sh
 Only libc6 is a hard dependency, so the package installs cleanly on any
 Debian/Ubuntu (even minimal).
EOF

cat > "$STAGING/DEBIAN/conffiles" <<'EOF'
/usr/share/dark-recon/config.yaml
/usr/share/dark-recon/tools_config.yaml
/usr/share/dark-recon/llm_config.yaml
EOF

echo "==> Writing maintainer scripts (postinst is non-fatal and fast)"
cat > "$STAGING/DEBIAN/postinst" <<'EOF'
#!/bin/sh
# postinst: configure Dark-Recon. ALWAYS exits 0 so the package can never
# fail to configure. It runs a fast, read-only prerequisites VERIFICATION now
# (immediate feedback at install time) and defers the heavy network INSTALL
# of Go security tools to first launch (the launcher auto-installs missing
# REQUIRED tools as the invoking user). Full bootstrap at install time is
# opt-in via: DARK_RECON_INSTALL_PREREQS=1 apt install ./dark-recon_*.deb
set -u

APP_DIR=/usr/share/dark-recon
STATE_DIR=/var/lib/dark-recon
ENGINE="$APP_DIR/scripts/check-prereqs.sh"

# State dir for the first-run marker (launcher falls back to a per-user
# marker if this isn't writable by the invoking user).
mkdir -p "$STATE_DIR" 2>/dev/null || true
chmod 0755 "$STATE_DIR" 2>/dev/null || true

# Ensure the bundled engine + wrapper are executable (dpkg preserves mode, but
# be defensive in case the archive was repacked).
chmod 0755 "$ENGINE" "$APP_DIR/scripts/install-tools.sh" 2>/dev/null || true

# apt runs postinst with a minimal PATH that omits /usr/local/bin and
# /root/go/bin; add the common system tool locations so the verification
# actually finds tools installed system-wide.
export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin:/root/go/bin:${PATH:-}"
[ -n "${HOME:-}" ] || export HOME=/root

echo
echo "==============================================================================="
echo " Dark-Recon - prerequisites verification"
echo "==============================================================================="

if [ "${DARK_RECON_SKIP_PREREQS:-0}" = "1" ]; then
	echo "  (DARK_RECON_SKIP_PREREQS=1 - verification skipped)"
elif [ -f "$ENGINE" ]; then
	if [ "${DARK_RECON_INSTALL_PREREQS:-0}" = "1" ]; then
		# Opt-in full bootstrap at install time: go install of required tools
		# (and optional ones with DARK_RECON_INSTALL_STRICT=1). May take minutes.
		_args="--install"
		[ "${DARK_RECON_INSTALL_STRICT:-0}" = "1" ] && _args="--install --strict"
		echo "  DARK_RECON_INSTALL_PREREQS=1 - installing missing tools now (may take a few minutes)..."
		# shellcheck disable=SC2086
		sh "$ENGINE" --no-color $_args || echo "  (some tools could not be installed - see report above)" >&2
	else
		# Read-only verification: fast, non-fatal. The authoritative per-user
		# check (with auto-install) runs on first launch / `dark-recon prereqs`.
		echo "  Read-only system check (running as root during install)."
		echo "  Authoritative per-user check: dark-recon prereqs"
		sh "$ENGINE" --no-color || true
	fi
else
	echo "  (prerequisites engine not found at $ENGINE - skipped)" >&2
fi

echo
cat <<NOTE
-------------------------------------------------------------------------------
 Dark-Recon configured.

   Start server : dark-recon --port 5000
   Config       : $APP_DIR/config.yaml
   Docs         : $APP_DIR/README.md

 On first launch Dark-Recon verifies its prerequisites and auto-installs the
 missing required Go security tools (subfinder, ffuf, httpx, webanalyze,
 katana, nuclei, subzy). Manual control:
   dark-recon prereqs                       # read-only status report
   dark-recon prereqs --install             # install missing required tools
   dark-recon prereqs --install --strict    # also install optional tools
   sudo $APP_DIR/scripts/install-tools.sh --strict

 Skip the first-run gate:  DARK_RECON_SKIP_PREREQS=1 dark-recon ...
-------------------------------------------------------------------------------
NOTE

if ! command -v go >/dev/null 2>&1; then
    echo "  (golang-go not installed - required to build the security tools: sudo apt install golang-go)"
fi

exit 0
EOF

cat > "$STAGING/DEBIAN/prerm" <<'EOF'
#!/bin/sh
# Best-effort: stop a running server before removal.
if command -v pkill >/dev/null 2>&1; then
    pkill -f "/usr/share/dark-recon/dark-recon" 2>/dev/null || true
fi
exit 0
EOF

cat > "$STAGING/DEBIAN/postrm" <<'EOF'
#!/bin/sh
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/dark-recon 2>/dev/null || true
    echo "Dark-Recon purged. Scan results kept in ~/dark_recon_results."
fi
exit 0
EOF

echo "==> Normalizing permissions"
find "$STAGING" -type d -exec chmod 0755 {} \;
find "$STAGING" -type f -exec chmod 0644 {} \;
chmod 0755 "$APPDIR/dark-recon" \
           "$APPDIR/scripts/check-prereqs.sh" \
           "$APPDIR/scripts/install-tools.sh" \
           "$STAGING/usr/local/bin/dark-recon" \
           "$STAGING/DEBIAN/postinst" \
           "$STAGING/DEBIAN/prerm" \
           "$STAGING/DEBIAN/postrm"

echo "==> Building .deb (root ownership via --root-owner-group)"
dpkg-deb --build --root-owner-group "$STAGING" "$DEB"

echo "==> Done"
ls -lh "$DEB"
echo
echo "Inspect:  dpkg-deb -I $DEB"
echo "Contents: dpkg-deb -c $DEB"
echo "Install:  sudo apt install ./$DEB   (or: sudo dpkg -i $DEB)"
