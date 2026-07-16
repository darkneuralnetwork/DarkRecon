#!/bin/sh
# ============================================================================
# Dark-Recon Installer
# ============================================================================
# Installs the Dark-Recon static binary on Linux and macOS.
#
#   1. Downloads the pre-built binary for your OS/arch from the latest GitHub
#      Release (assets are named dark-recon-<os>-<arch>, produced by
#      .github/workflows/release.yml).
#   2. Verifies its sha256 against the published checksums.txt.
#   3. Installs it to /usr/local/bin (when run as root / writable) or
#      ~/.local/bin otherwise.
#   4. Runs the prerequisites check so you can see which external security
#      tools (subfinder, httpx, nuclei, ...) still need installing.
#
# If no pre-built binary is available for your platform, it falls back to
# `go install`, then to a build-from-source clone.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/yourname/dark-recon/main/install.sh | sh
#
# Options:
#   --version <tag>   Install a specific release tag (default: latest)
#   --bin <path>      Install to this exact path
#   --skip-check      Don't run the prerequisites check at the end
#   --owner <owner>   GitHub owner (default: yourname, or $GITHUB_OWNER)
#   --repo <repo>     GitHub repo  (default: dark-recon, or $GITHUB_REPO)
#   -h, --help        Show this help
# ============================================================================
set -eu

# ── Config ──────────────────────────────────────────────────────────────────
OWNER="${GITHUB_OWNER:-yourname}"
REPO="${GITHUB_REPO:-dark-recon}"
BIN_NAME="dark-recon"
VERSION="latest"
BIN_DIR=""
SKIP_CHECK=0

# ── Colors (disabled when not a tty) ────────────────────────────────────────
if [ -t 1 ]; then
	ESC=$(printf '\033')
	RED="${ESC}[31m"; GREEN="${ESC}[32m"; YELLOW="${ESC}[33m"
	CYAN="${ESC}[36m"; BOLD="${ESC}[1m"; RESET="${ESC}[0m"
else
	RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

info()  { printf "${CYAN}▸${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}!${RESET} %s\n" "$*" >&2; }
die()   { printf "${RED}✗${RESET} %s\n" "$*" >&2; exit 1; }

# ── Arg parsing ─────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
	case "$1" in
		--version)    VERSION="$2"; shift 2 ;;
		--bin)        BIN_DIR="$2"; shift 2 ;;
		--skip-check) SKIP_CHECK=1; shift ;;
		--owner)      OWNER="$2"; shift 2 ;;
		--repo)       REPO="$2"; shift 2 ;;
		-h|--help)
			awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
			exit 0 ;;
		*) die "Unknown option: $1 (try --help)" ;;
	esac
done

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
	|| die "Need curl or wget to download the binary."

# ── OS / arch detection ─────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
	linux)  OS="linux" ;;
	darwin) OS="darwin" ;;
	*) die "Unsupported OS: $(uname -s) (Dark-Recon ships linux & macOS builds)" ;;
esac
case "$ARCH" in
	x86_64|amd64) ARCH="amd64" ;;
	aarch64|arm64) ARCH="arm64" ;;
	*) die "Unsupported architecture: $ARCH (Dark-Recon ships amd64 & arm64 builds)" ;;
esac

ASSET="${BIN_NAME}-${OS}-${ARCH}"
if [ "$VERSION" = "latest" ]; then
	DL_BASE="https://github.com/${OWNER}/${REPO}/releases/latest/download"
else
	DL_BASE="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}"
fi

printf "${BOLD}Dark-Recon installer${RESET}  (${OWNER}/${REPO}, ${OS}/${ARCH})\n"

# ── Resolve install directory ───────────────────────────────────────────────
if [ -z "$BIN_DIR" ]; then
	if [ "$(id -u)" -eq 0 ] && [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		BIN_DIR="/usr/local/bin"
	else
		BIN_DIR="${HOME}/.local/bin"
		mkdir -p "$BIN_DIR"
	fi
fi
[ -d "$BIN_DIR" ] || mkdir -p "$BIN_DIR" || die "Cannot create install dir: $BIN_DIR"

# ── Download helper (curl or wget) ──────────────────────────────────────────
# http_get <url> <output_file>   (prints nothing on success)
http_get() {
	_url="$1"; _out="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$_url" -o "$_out"
	else
		wget -q "$_url" -O "$_out"
	fi
}

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t dr-install)"
trap 'rm -rf "$TMP"' EXIT

BINARY_PATH="${BIN_DIR}/${BIN_NAME}"
BUILT=0

# ── Try 1: pre-built release binary ─────────────────────────────────────────
info "Downloading ${ASSET} from ${DL_BASE} ..."
if http_get "${DL_BASE}/${ASSET}" "${TMP}/${ASSET}"; then
	# Verify checksum if checksums.txt is published.
	if http_get "${DL_BASE}/checksums.txt" "${TMP}/checksums.txt"; then
		EXPECTED="$(grep -E "[[:space:]]${ASSET}\$" "${TMP}/checksums.txt" | awk '{print $1}' | head -1)"
		if [ -n "$EXPECTED" ]; then
			ACTUAL="$(sha256sum "${TMP}/${ASSET}" | awk '{print $1}')"
			if [ "$ACTUAL" != "$EXPECTED" ]; then
				warn "Checksum mismatch for ${ASSET} (expected ${EXPECTED}, got ${ACTUAL}) — refusing to install."
				rm -f "${TMP}/${ASSET}"
			else
				ok "Checksum verified (${ACTUAL})"
			fi
		else
			warn "No checksum entry for ${ASSET} in checksums.txt — skipping verification."
		fi
	else
		warn "checksums.txt unavailable — skipping verification."
	fi
fi

if [ -f "${TMP}/${ASSET}" ]; then
	install -m 0755 "${TMP}/${ASSET}" "$BINARY_PATH"
	ok "Installed ${BIN_NAME} → ${BINARY_PATH}"
	BUILT=1
fi

# ── Try 2: go install ───────────────────────────────────────────────────────
if [ "$BUILT" -eq 0 ]; then
	warn "No pre-built binary for ${OS}/${ARCH} (or download failed)."
	if command -v go >/dev/null 2>&1; then
		info "Falling back to: go install github.com/${OWNER}/${REPO}/cmd/${BIN_NAME}@${VERSION}"
		if GOFLAGS= go install "github.com/${OWNER}/${REPO}/cmd/${BIN_NAME}@${VERSION}" 2>"${TMP}/go.log"; then
			GOBIN_DIR="$(go env GOBIN 2>/dev/null || true)"
			[ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH 2>/dev/null)/bin"
			if [ -f "${GOBIN_DIR}/${BIN_NAME}" ]; then
				install -m 0755 "${GOBIN_DIR}/${BIN_NAME}" "$BINARY_PATH"
				ok "Installed ${BIN_NAME} → ${BINARY_PATH}"
				BUILT=1
			fi
		else
			warn "go install failed: $(tail -n 3 "${TMP}/go.log" 2>/dev/null)"
		fi
	else
		warn "'go' not found — cannot use the go install fallback."
	fi
fi

# ── Try 3: build from source ────────────────────────────────────────────────
if [ "$BUILT" -eq 0 ]; then
	info "Falling back to building from source ..."
	command -v go >/dev/null 2>&1 || die "Cannot install: no pre-built binary, and 'go' is not installed (install Go 1.25+ and re-run)."
	command -v git >/dev/null 2>&1 || die "Cannot build from source: 'git' is not installed."
	SRC="${TMP}/src"
	info "Cloning ${OWNER}/${REPO} ..."
	git clone --depth 1 "https://github.com/${OWNER}/${REPO}.git" "$SRC" 2>"${TMP}/git.log" \
		|| die "git clone failed (set --owner/--repo or GITHUB_OWNER to your fork)."
	( cd "$SRC" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${TMP}/${BIN_NAME}" ./cmd/dark-recon/ ) \
		|| die "go build failed."
	install -m 0755 "${TMP}/${BIN_NAME}" "$BINARY_PATH"
	ok "Built and installed ${BIN_NAME} → ${BINARY_PATH}"
	BUILT=1
fi

# ── PATH hint ───────────────────────────────────────────────────────────────
case ":${PATH}:" in
	*":${BIN_DIR}:"*) ;;
	*)
		warn "${BIN_DIR} is not on your PATH."
		printf "    Add it to your shell profile:\n      export PATH=\"%s:\$PATH\"\n" "$BIN_DIR"
		;;
esac

# ── Version check ───────────────────────────────────────────────────────────
if "$BINARY_PATH" -h >/dev/null 2>&1; then
	ok "${BIN_NAME} installed successfully."
else
	warn "Installed ${BINARY_PATH}, but 'dark-recon -h' did not return 0 — check the binary."
fi

# ── Prerequisites check ─────────────────────────────────────────────────────
if [ "$SKIP_CHECK" -eq 1 ]; then
	printf "\n${GREEN}Done.${RESET} Run a scan with:  ${BIN_NAME} -port 5000\n"
	exit 0
fi

printf "\n${BOLD}Running prerequisites check ...${RESET}\n"
CHECK="${TMP}/check-prereqs.sh"
if http_get "https://raw.githubusercontent.com/${OWNER}/${REPO}/main/scripts/check-prereqs.sh" "$CHECK"; then
	sh "$CHECK" --strict || warn "Some external tools are missing (see report above)."
else
	warn "Could not fetch scripts/check-prereqs.sh — run 'make check-prereqs' from a source checkout."
fi

printf "\n${GREEN}Done.${RESET} Start the server with:  ${BIN_NAME} -port 5000\n"
printf "Install missing security tools with:  ${BIN_NAME} then 'make install-tools' from a source checkout.\n"
exit 0
