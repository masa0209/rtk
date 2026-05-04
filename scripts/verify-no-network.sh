#!/usr/bin/env bash
# verify-no-network.sh — Static + runtime evidence that this fork performs
# no outbound network calls.
#
# Why this exists:
#   The upstream rtk-ai/rtk binary contains an opt-out telemetry pinger
#   (`ureq` HTTP client). This fork removed the telemetry module and its
#   dependencies. This script gives you reproducible evidence of that
#   removal — useful when auditing the binary or convincing security
#   reviewers.
#
# Usage:
#   bash scripts/verify-no-network.sh            # static checks only
#   bash scripts/verify-no-network.sh --runtime  # also run live ss/lsof probe
#
# Exit codes:
#   0 — all checks passed (no HTTP client deps, no suspicious strings)
#   1 — at least one check failed
#
# This script is read-only and does NOT modify the system.

set -u
# Intentionally not `set -e`: we want to run all checks and aggregate failures.

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BOLD=$'\033[1m'
NC=$'\033[0m'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

FAILED=0
PASSED=0

pass() { printf "  ${GREEN}[PASS]${NC} %s\n" "$1"; PASSED=$((PASSED + 1)); }
fail() { printf "  ${RED}[FAIL]${NC} %s\n" "$1"; FAILED=$((FAILED + 1)); }
info() { printf "  ${YELLOW}[INFO]${NC} %s\n" "$1"; }
section() { printf "\n${BOLD}== %s ==${NC}\n" "$1"; }

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf "${RED}Missing required tool:${NC} %s\n" "$1" >&2
        exit 2
    fi
}

require cargo

# Prefer ripgrep when available, fall back to grep -E.
if command -v rg >/dev/null 2>&1; then
    GREP_CMD() { rg --no-heading --color=never "$@"; }
else
    GREP_CMD() { grep -E "$@"; }
fi

# ---------------------------------------------------------------------------
section "1. Cargo dependency tree"
# ---------------------------------------------------------------------------
# Bans on outbound HTTP / async-IO crates that the upstream telemetry used
# (or that any future regression would likely re-introduce).
BANNED_CRATES='reqwest|ureq|hyper|isahc|surf|h2|tokio|async-std|rustls|native-tls|openssl-sys'

if cargo tree --quiet --edges normal 2>/dev/null \
        | GREP_CMD -i "^[^a-zA-Z]*($BANNED_CRATES) " \
        >/tmp/rtk-banned-deps.$$; then
    fail "Banned HTTP/async crates found in cargo tree:"
    sed 's/^/      /' /tmp/rtk-banned-deps.$$
else
    pass "No banned HTTP/async crates in cargo tree"
fi
rm -f /tmp/rtk-banned-deps.$$

# ---------------------------------------------------------------------------
section "2. Source tree string scan"
# ---------------------------------------------------------------------------
# Look for residual telemetry references and HTTP URLs targeting the old
# telemetry endpoints. We exclude .git, target, docs of upstream history,
# and this script itself.
SCAN_PATHS=(src Cargo.toml Cargo.lock)

if GREP_CMD -i -n 'telemetry|RTK_TELEMETRY' "${SCAN_PATHS[@]}" \
        >/tmp/rtk-telemetry-refs.$$ 2>/dev/null; then
    # Some hits may be benign (legacy comments, "ignored" tests). Surface them
    # so the human auditor can inspect, but only fail on `pub fn`/`mod`/`use`.
    if GREP_CMD -E '^[^:]+:[0-9]+:.*(pub (fn|mod|struct)|^use ).*telemetry' \
            /tmp/rtk-telemetry-refs.$$ >/dev/null; then
        fail "Active telemetry symbols found in source:"
        GREP_CMD -E '^[^:]+:[0-9]+:.*(pub (fn|mod|struct)|^use ).*telemetry' \
            /tmp/rtk-telemetry-refs.$$ | sed 's/^/      /'
    else
        pass "No active telemetry symbols (only comments / legacy mentions)"
        info "Remaining mentions (informational, expected):"
        head -n 5 /tmp/rtk-telemetry-refs.$$ | sed 's/^/      /'
    fi
else
    pass "No 'telemetry' references in source"
fi
rm -f /tmp/rtk-telemetry-refs.$$

# ---------------------------------------------------------------------------
section "3. Built binary string scan"
# ---------------------------------------------------------------------------
BIN_PATH=""
if [ -x "target/release/rtk" ]; then
    BIN_PATH="target/release/rtk"
elif [ -x "target/debug/rtk" ]; then
    BIN_PATH="target/debug/rtk"
fi

if [ -z "$BIN_PATH" ]; then
    info "No built binary found (target/release/rtk or target/debug/rtk)."
    info "Run 'cargo build --release' first to enable this check."
else
    info "Inspecting binary: $BIN_PATH"
    if strings "$BIN_PATH" \
            | GREP_CMD -i 'https?://[a-zA-Z0-9._-]*(rtk-ai|telemetry|ingest|analytics)' \
            >/tmp/rtk-bin-urls.$$; then
        fail "Suspicious telemetry-style URLs embedded in binary:"
        sort -u /tmp/rtk-bin-urls.$$ | head -n 20 | sed 's/^/      /'
    else
        pass "No telemetry-style URLs in binary"
    fi
    rm -f /tmp/rtk-bin-urls.$$

    # Symbol-level check: HTTP client crate symbols should not be linked.
    if command -v nm >/dev/null 2>&1; then
        if nm -gU "$BIN_PATH" 2>/dev/null \
                | GREP_CMD -i '(reqwest|ureq|hyper|isahc)' \
                >/tmp/rtk-bin-syms.$$; then
            fail "HTTP client symbols linked into binary:"
            head -n 5 /tmp/rtk-bin-syms.$$ | sed 's/^/      /'
        else
            pass "No HTTP client symbols linked into binary"
        fi
        rm -f /tmp/rtk-bin-syms.$$
    fi
fi

# ---------------------------------------------------------------------------
section "4. Runtime probe (optional)"
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--runtime" ]; then
    if [ -z "$BIN_PATH" ]; then
        info "Skipping runtime probe: no binary built."
    else
        info "Running '$BIN_PATH gain' under lsof to inspect open sockets..."
        # Run rtk in the background, snapshot its sockets, then let it finish.
        "$BIN_PATH" gain >/dev/null 2>&1 &
        RTK_PID=$!
        # Tiny grace period for the process to open any sockets it would.
        sleep 0.05 2>/dev/null || sleep 1
        if command -v lsof >/dev/null 2>&1; then
            if lsof -p "$RTK_PID" -nP 2>/dev/null \
                    | GREP_CMD -E 'TCP|UDP|IPv4|IPv6' \
                    | GREP_CMD -v '127\.0\.0\.1|::1|localhost' \
                    >/tmp/rtk-rt-sockets.$$; then
                fail "Non-loopback sockets observed during 'rtk gain':"
                head -n 5 /tmp/rtk-rt-sockets.$$ | sed 's/^/      /'
            else
                pass "No non-loopback sockets during 'rtk gain'"
            fi
            rm -f /tmp/rtk-rt-sockets.$$
        else
            info "lsof not available; skipping socket probe"
        fi
        wait "$RTK_PID" 2>/dev/null || true
    fi
else
    info "Runtime probe skipped (pass --runtime to enable)"
fi

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
printf "  Passed: %s%d%s   Failed: %s%d%s\n" \
    "$GREEN" "$PASSED" "$NC" "$RED" "$FAILED" "$NC"

if [ "$FAILED" -gt 0 ]; then
    printf "\n${RED}${BOLD}FAIL${NC} — at least one check failed. Review above.\n"
    exit 1
fi
printf "\n${GREEN}${BOLD}OK${NC} — fork has no detectable outbound network surface.\n"
exit 0
