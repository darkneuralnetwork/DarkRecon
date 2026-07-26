#!/bin/sh
# =============================================================================
# check-prereqs.sh — verify (and optionally install) everything Dark-Recon needs
# =============================================================================
# This is the SINGLE SOURCE OF TRUTH for Dark-Recon's runtime prerequisites.
# The tool table below is kept in sync with internal/installer/installer.go
# (BuiltinTools) so the CLI, the web UI and the .deb all agree on what is
# required, optional, and how each tool is installed/checked.
#
# It checks, in order:
#   1. System requirements  — OS, architecture, libc6, free disk, kernel
#   2. Build toolchain      — go (>= 1.25), git, curl, ca-certificates
#   3. Core pipeline tools  — REQUIRED Go security tools (subfinder, ffuf, ...)
#   4. Advanced modules     — OPTIONAL tools (nmap, naabu, chaos, ...)
#   5. Data sets            — SecLists wordlists, nuclei templates
#
# For every tool it also captures and prints the installed version.
#
# Modes:
#   check-prereqs.sh                       read-only report (default)
#   check-prereqs.sh --strict              exit non-zero if an OPTIONAL item is missing
#   check-prereqs.sh --install             auto-install missing REQUIRED items
#   check-prereqs.sh --install --strict    auto-install REQUIRED + OPTIONAL items
#   check-prereqs.sh --no-color            disable ANSI colours
#   check-prereqs.sh -h|--help             show this help
#
# Exit codes:
#   0  all required items present (and, with --install, successfully installed)
#   1  one or more REQUIRED items missing / failed to install
#   2  an OPTIONAL item missing while --strict is set
#
# Run:  bash scripts/check-prereqs.sh [--install] [--strict]
#       (also works with plain sh / dash)
# =============================================================================
set -u

# ── Args ─────────────────────────────────────────────────────────────────────
STRICT=0
INSTALL=0
NO_COLOR=0
for _a in "$@"; do
	case "$_a" in
		--strict)    STRICT=1 ;;
		--install)   INSTALL=1 ;;
		--no-color)  NO_COLOR=1 ;;
		-h|--help)
			awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
			exit 0 ;;
		*) printf 'Unknown option: %s (try --help)\n' "$_a" >&2; exit 64 ;;
	esac
done

# ── Colours (disabled when not a tty or --no-color) ──────────────────────────
if [ -t 1 ] && [ "$NO_COLOR" -eq 0 ]; then
	ESC=$(printf '\033')
	GREEN="${ESC}[32m"; YELLOW="${ESC}[33m"; RED="${ESC}[31m"
	CYAN="${ESC}[36m"; BOLD="${ESC}[1m"; DIM="${ESC}[2m"; RESET="${ESC}[0m"
else
	GREEN=''; YELLOW=''; RED=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# ── Helpers ──────────────────────────────────────────────────────────────────
LOG="$(mktemp 2>/dev/null || mktemp -t dr-prereqs)"
trap 'rm -f "$LOG" 2>/dev/null' EXIT

# A tool is "present" if it is on PATH or in ~/go/bin (matches the Go binary's
# executor.IsInstalled: exec.LookPath + $HOME/go/bin).
have() { command -v "$1" >/dev/null 2>&1 || [ -x "${HOME}/go/bin/$1" ]; }

# Full path to a tool, or empty.
tool_path() {
	if command -v "$1" >/dev/null 2>&1; then
		command -v "$1"
	elif [ -x "${HOME}/go/bin/$1" ]; then
		echo "${HOME}/go/bin/$1"
	fi
}

# Extract a x.y[.z] version token from a tool's check command output.
tool_version() {
	_name="$1"; _check="$2"
	[ -z "$_check" ] && { echo ""; return; }
	_out=$(sh -c "$_check" 2>&1) || true
	echo "$_out" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

ok()    { printf "  ${GREEN}✓${RESET}  %-13s %s\n" "$1" "${2:-}"; }
miss()  { printf "  ${RED}✗${RESET}  %-13s ${RED}missing${RESET}  %s\n" "$1" "${2:-}"; }
opt()   { printf "  ${YELLOW}-${RESET}  %-13s ${YELLOW}optional${RESET}  %s\n" "$1" "${2:-}"; }
note()  { printf "  ${DIM}%s${RESET}\n" "$1"; }

# ── Privilege / GOBIN setup (only used when --install) ───────────────────────
# Required pipeline tools are all Go-based and install WITHOUT sudo (go install
# to ~/go/bin, or /usr/local/bin when run as root). apt/pip tools are optional.
CAN_SUDO=0
if [ "$(id -u)" -eq 0 ]; then
	CAN_SUDO=1
elif command -v sudo >/dev/null 2>&1; then
	CAN_SUDO=1   # will prompt interactively if not passwordless
fi

if [ "$INSTALL" -eq 1 ]; then
	# Where `go install` drops binaries. Root -> /usr/local/bin (on PATH for
	# everyone); otherwise ~/go/bin (what the Go binary also checks).
	if [ "$(id -u)" -eq 0 ]; then
		GOBIN="${GOBIN:-/usr/local/bin}"
	else
		GOBIN="${GOBIN:-${HOME}/go/bin}"
	fi
	export GOBIN
	mkdir -p "$GOBIN" 2>/dev/null || true
	export PATH="$GOBIN:$PATH"
fi

# Best-effort: install golang-go if missing and we have sudo.
try_install_go() {
	if have go; then return 0; fi
	if [ "$CAN_SUDO" -eq 1 ]; then
		sudo apt-get update -qq >>"$LOG" 2>&1 || true
		sudo apt-get install -y golang-go >>"$LOG" 2>&1 || return 1
		have go && return 0
	fi
	return 1
}

# install_tool <name> <method> <install_cmd>
install_tool() {
	_name="$1"; _method="$2"; _icmd="$3"
	case "$_method" in
		go)
			if ! have go; then
				if try_install_go; then :; else
					printf "  ${RED}✗${RESET}  %-13s ${RED}need 'go'${RESET}  install: sudo apt install golang-go\n" "$_name"
					return 1
				fi
			fi
			;;
		apt)
			if [ "$CAN_SUDO" -eq 0 ]; then
				printf "  ${RED}✗${RESET}  %-13s ${RED}need sudo${RESET}  %s\n" "$_name" "$_icmd"
				return 1
			fi
			;;
		pip)
			_PIP=""
			command -v pip  >/dev/null 2>&1 && _PIP=pip
			command -v pip3 >/dev/null 2>&1 && _PIP=pip3
			if [ -z "$_PIP" ]; then
				printf "  ${RED}✗${RESET}  %-13s ${RED}need pip${RESET}  install: sudo apt install python3-pip\n" "$_name"
				return 1
			fi
			;;
	esac
	printf "  ${CYAN}▸${RESET}  %-13s installing ... " "$_name"
	if sh -c "$_icmd" >>"$LOG" 2>&1; then
		if have "$_name"; then echo "${GREEN}OK${RESET}"; return 0; fi
		echo "${YELLOW}done${RESET} ${DIM}(re-login or add $GOBIN to PATH may be needed)${RESET}"
		return 0
	fi
	echo "${RED}FAILED${RESET} ${DIM}(see $LOG)${RESET}"
	return 1
}

REQ_MISSING=0
OPT_MISSING=0

# ── The tool table (mirrors internal/installer/installer.go BuiltinTools) ────
# Fields: name|level|method|check_cmd|install_cmd|hint
#   level: REQ (required) | OPT (optional)
TOOLS=$(cat <<'EOF'
subfinder|REQ|go|subfinder -version|go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|go install .../subfinder
ffuf|REQ|go|ffuf -V|go install github.com/ffuf/ffuf/v2@latest|go install .../ffuf
httpx|REQ|go|httpx -version|go install github.com/projectdiscovery/httpx/cmd/httpx@latest|go install .../httpx
webanalyze|REQ|go|webanalyze -h|go install github.com/rverton/webanalyze/cmd/webanalyze@latest|go install .../webanalyze
katana|REQ|go|katana -version|go install github.com/projectdiscovery/katana/cmd/katana@latest|go install .../katana
nuclei|REQ|go|nuclei -version|go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|go install .../nuclei
subzy|REQ|go|subzy version|go install github.com/PentestPad/subzy@latest|go install .../subzy (was LukaSikic, renamed upstream)
nmap|OPT|apt|nmap --version|sudo apt-get install -y nmap|sudo apt install nmap
naabu|OPT|go|naabu -version|go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|go install .../naabu
chaos|OPT|go|chaos -version|go install github.com/projectdiscovery/chaos/cmd/chaos@latest|go install .../chaos (needs PDCP_API_KEY)
trufflehog|OPT|go|trufflehog --version|go install github.com/trufflesecurity/trufflehog/v3@latest|go install .../trufflehog
gitleaks|OPT|go|gitleaks version|go install github.com/gitleaks/gitleaks/v8@latest|go install .../gitleaks
wafw00f|OPT|pip|wafw00f -V|pip install --user wafw00f|pip install wafw00f
arjun|OPT|pip|arjun --version|pip install --user arjun|pip install arjun
EOF
)

# =============================================================================
# 1. System requirements
# =============================================================================
printf "${BOLD}[1/5] System requirements${RESET}\n"

OS_K="$(uname -s 2>/dev/null || echo unknown)"
ARCH_K="$(uname -m 2>/dev/null || echo unknown)"
case "$OS_K" in
	Linux)  ok "os" "Linux ($ARCH_K)" ;;
	*)      miss "os" "$OS_K — Dark-Recon targets Linux (debian/ubuntu/parrot)"; REQ_MISSING=$((REQ_MISSING+1)) ;;
esac
case "$ARCH_K" in
	x86_64|amd64)  ok "arch" "amd64" ;;
	aarch64|arm64) ok "arch" "arm64" ;;
	*)             miss "arch" "$ARCH_K — build ships amd64 & arm64"; REQ_MISSING=$((REQ_MISSING+1)) ;;
esac

# libc6 — the only hard .deb dependency; effectively always present on Debian.
if command -v ldd >/dev/null 2>&1 && ldd --version 2>/dev/null | head -1 | grep -qi glibc; then
	ok "libc6" "glibc ($(ldd --version 2>/dev/null | head -1 | sed 's/.*version //;s/,//'))"
elif [ -f /lib/x86_64-linux-gnu/libc.so.6 ] || [ -f /lib/aarch64-linux-gnu/libc.so.6 ] || [ -f /lib64/libc.so.6 ]; then
	ok "libc6" "present"
else
	miss "libc6" "not detected — Dark-Recon .deb Depends: libc6"; REQ_MISSING=$((REQ_MISSING+1))
fi

# Free disk: ~50MB for binaries + output data; recommend 1GB headroom.
HOME_FREE_MB=$(df -m "${HOME:-/}" 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "$HOME_FREE_MB" ] && [ "$HOME_FREE_MB" -ge 1024 ]; then
	ok "disk" "${HOME_FREE_MB} MB free in ${HOME}"
elif [ -n "$HOME_FREE_MB" ]; then
	opt "disk" "${HOME_FREE_MB} MB free in ${HOME} (>= 1024 MB recommended)"
	OPT_MISSING=$((OPT_MISSING+1))
else
	opt "disk" "could not measure free space"
	OPT_MISSING=$((OPT_MISSING+1))
fi

# Kernel version (informational).
ok "kernel" "$(uname -r 2>/dev/null || echo unknown)"

# =============================================================================
# 2. Build toolchain
# =============================================================================
printf "\n${BOLD}[2/5] Build toolchain${RESET}\n"

# NOTE: the shipped dark-recon binary is pre-built & static, so `go` is only
# needed to `go install` the security tools (subfinder, nuclei, ...). The Go
# toolchain auto-downloads a compatible compiler on demand, so any reasonably
# recent system Go works — we therefore require go's PRESENCE, not a specific
# minimum, and report its version informationally.
if have go; then
	# `go version` is cwd-dependent (toolchain switching inside a module that
	# declares a newer `go` directive). GOTOOLCHAIN=local pins the report to the
	# actually-installed system compiler so it is stable.
	GO_RAW="$(GOTOOLCHAIN=local go version 2>/dev/null | sed -n 's/.*go\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
	[ -n "$GO_RAW" ] || GO_RAW="$(go version 2>/dev/null | sed -n 's/.*go\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
	ok "go" "v${GO_RAW:-?} ($(command -v go))"
	GO_MAJ="${GO_RAW%%.*}"; GO_MIN="${GO_RAW#*.}"
	if [ -n "$GO_MAJ" ] && [ -n "$GO_MIN" ] && { [ "$GO_MAJ" -lt 1 ] || { [ "$GO_MAJ" -eq 1 ] && [ "$GO_MIN" -lt 21 ]; }; }; then
		note "go v$GO_RAW is old; the toolchain will auto-download a newer Go when building tools (needs network)"
	fi
else
	if [ "$INSTALL" -eq 1 ] && try_install_go; then
		ok "go" "installed ($(command -v go))"
	else
		miss "go" "not installed (sudo apt install golang-go) — needed to install security tools"
		REQ_MISSING=$((REQ_MISSING+1))
	fi
fi

# git / curl / ca-certificates: needed by go install, nuclei -update-templates, etc.
for _t in git curl; do
	if have "$_t"; then ok "$_t" "$(tool_path "$_t")"; else
		if [ "$INSTALL" -eq 1 ] && [ "$CAN_SUDO" -eq 1 ]; then
			sudo apt-get install -y "$_t" >>"$LOG" 2>&1 && have "$_t" && { ok "$_t" "installed"; continue; }
		fi
		miss "$_t" "sudo apt install $_t"; REQ_MISSING=$((REQ_MISSING+1))
	fi
done

if [ -f /etc/ssl/certs/ca-certificates.crt ] || have update-ca-certificates; then
	ok "ca-certificates" "present"
else
	if [ "$INSTALL" -eq 1 ] && [ "$CAN_SUDO" -eq 1 ]; then
		sudo apt-get install -y ca-certificates >>"$LOG" 2>&1 && { ok "ca-certificates" "installed"; }
	else
		opt "ca-certificates" "sudo apt install ca-certificates (TLS for tool/template downloads)"
		OPT_MISSING=$((OPT_MISSING+1))
	fi
fi

# =============================================================================
# 3–4. Security tools (required core pipeline + optional advanced modules)
# =============================================================================
printf "\n${BOLD}[3/5] Core pipeline tools (required)${RESET}\n"
printf "${BOLD}[4/5] Advanced modules (optional)${RESET}\n"

echo "$TOOLS" | while IFS='|' read -r name level method check install hint; do
	[ -z "$name" ] && continue
	case "$level" in REQ|OPT) ;; *) continue ;; esac

	if have "$name"; then
		ver="$(tool_version "$name" "$check")"
		ok "$name" "$(tool_path "$name")${ver:+  v$ver}"
		continue
	fi

	# Missing. Decide install vs report.
	_do_install=0
	[ "$level" = "REQ" ] && [ "$INSTALL" -eq 1 ] && _do_install=1
	[ "$level" = "OPT" ] && [ "$INSTALL" -eq 1 ] && [ "$STRICT" -eq 1 ] && _do_install=1

	if [ "$_do_install" -eq 1 ]; then
		# install_tool runs in a subshell-less context; capture result via file.
		if install_tool "$name" "$method" "$install"; then
			ver="$(tool_version "$name" "$check")"
			ok "$name" "$(tool_path "$name")${ver:+  v$ver}"
		else
			[ "$level" = "REQ" ] && miss "$name" "$hint" || opt "$name" "$hint"
			# propagate counts via marker files (we're in a | subshell)
			[ "$level" = "REQ" ] && touch "$LOG.req" || touch "$LOG.opt"
		fi
	else
		[ "$level" = "REQ" ] && { miss "$name" "$hint"; touch "$LOG.req"; } || { opt "$name" "$hint"; touch "$LOG.opt"; }
	fi
done
# The tool loop runs in a subshell (pipe), so fold its counts back in.
[ -f "$LOG.req" ] && REQ_MISSING=$((REQ_MISSING+1))
[ -f "$LOG.opt" ] && OPT_MISSING=$((OPT_MISSING+1))
rm -f "$LOG.req" "$LOG.opt" 2>/dev/null

# =============================================================================
# 5. Data sets — SecLists wordlists & nuclei templates
# =============================================================================
printf "\n${BOLD}[5/5] Wordlists & templates (recommended)${RESET}\n"

SECLISTS="/usr/share/wordlists/seclists"
if [ -d "$SECLISTS" ] && [ -n "$(ls -A "$SECLISTS" 2>/dev/null)" ]; then
	ok "seclists" "$SECLISTS"
else
	if [ "$INSTALL" -eq 1 ] && [ "$STRICT" -eq 1 ] && [ "$CAN_SUDO" -eq 1 ]; then
		printf "  ${CYAN}▸${RESET}  %-13s installing ... " "seclists"
		if sudo apt-get install -y seclists >>"$LOG" 2>&1 && [ -d "$SECLISTS" ]; then
			echo "${GREEN}OK${RESET}"; ok "seclists" "$SECLISTS"
		else
			echo "${RED}FAILED${RESET}"; opt "seclists" "sudo apt install seclists"; OPT_MISSING=$((OPT_MISSING+1))
		fi
	else
		opt "seclists" "sudo apt install seclists  (directory/DNS wordlists)"
		OPT_MISSING=$((OPT_MISSING+1))
	fi
fi

NUCLEI_TPL="${NUCLEI_TPL:-${HOME}/nuclei-templates}"
if [ -d "$NUCLEI_TPL" ] && [ -n "$(ls -A "$NUCLEI_TPL" 2>/dev/null)" ]; then
	ok "nuclei-templates" "$NUCLEI_TPL"
else
	if [ "$INSTALL" -eq 1 ] && have nuclei; then
		printf "  ${CYAN}▸${RESET}  %-13s updating ... " "nuclei-templates"
		if nuclei -update-templates >>"$LOG" 2>&1 && [ -d "$NUCLEI_TPL" ] && [ -n "$(ls -A "$NUCLEI_TPL" 2>/dev/null)" ]; then
			echo "${GREEN}OK${RESET}"; ok "nuclei-templates" "$NUCLEI_TPL"
		else
			echo "${RED}FAILED${RESET}"; opt "nuclei-templates" "run: nuclei -update-templates"; OPT_MISSING=$((OPT_MISSING+1))
		fi
	else
		opt "nuclei-templates" "run: nuclei -update-templates"
		OPT_MISSING=$((OPT_MISSING+1))
	fi
fi

# =============================================================================
# Summary
# =============================================================================
printf "\n${BOLD}──────── summary ────────${RESET}\n"
if [ "$REQ_MISSING" -eq 0 ]; then
	printf "${GREEN}All required tools present.${RESET}\n"
else
	printf "${RED}%d required item(s) missing.${RESET}\n" "$REQ_MISSING"
fi
if [ "$OPT_MISSING" -gt 0 ]; then
	printf "${YELLOW}%d optional item(s) missing — advanced modules affected.${RESET}\n" "$OPT_MISSING"
fi

printf "\nInstall missing tools with:\n"
if [ "$INSTALL" -eq 0 ]; then
	printf "  bash scripts/check-prereqs.sh --install        (required only)\n"
	printf "  bash scripts/check-prereqs.sh --install --strict  (required + optional)\n"
	printf "  make install-tools                             (wraps the above)\n"
fi
if [ -s "$LOG" ]; then
	printf "${DIM}install log: %s${RESET}\n" "$LOG"
	trap - EXIT   # keep the log so the user can inspect failures
fi

if [ "$REQ_MISSING" -gt 0 ]; then
	exit 1
fi
if [ "$STRICT" -eq 1 ] && [ "$OPT_MISSING" -gt 0 ]; then
	exit 2
fi
exit 0
