#!/bin/bash
# OMEGA-ZERODAY HUNTER v2.0 — CLI Wrapper
# Routes to Python TUI (interactive) or C engine (direct)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="/root/.qwenpaw/workspaces/default/ARSENAL/omega-zeroday"
C_ENGINE="/usr/local/bin/omega-engine"
PYTHON_TUI="${ENGINE_DIR}/ui/omega_tui.py"
PYTHON_V1="${ENGINE_DIR}/omega_zeroday.py"

# Colors
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RESET='\033[0m'

banner() {
    echo -e "${RED}"
    echo "  ██████  ██ ███████ ████████  ██████   ██████  ██████  ██████  ███████"
    echo "  ██   ██ ██ ██         ██    ██    ██ ██      ██    ██ ██   ██ ██     "
    echo "  ██████  ██ ███████    ██    ██    ██ ██      ██    ██ ██████  █████  "
    echo "  ██   ██ ██      ██    ██    ██    ██ ██      ██    ██ ██   ██ ██     "
    echo "  ██████  ██ ███████    ██     ██████   ██████  ██████  ██   ██ ███████"
    echo -e "${YELLOW}       ⚡ Z E R O D A Y   H U N T E R   v2.0 ⚡${RESET}"
    echo -e "${CYAN}       By Ghost Killer Omega / Mirzacyberhub${RESET}"
    echo ""
}

# Parse args
INTERACTIVE=true
TARGET=""
ENGINES=""
TIMEOUT="5"
THREADS="20"
COOKIE=""
JSON=false
QUIET=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-menu|-n) INTERACTIVE=false; shift ;;
        --json|-j) JSON=true; shift ;;
        --quiet|-q) QUIET=true; shift ;;
        --v1) exec python3 "$PYTHON_V1" "${@/ --v1/}"; shift ;;
        --version|-v)
            echo "omega-zeroday v2.0.0 (C engine + Python TUI)"
            [ -f "$C_ENGINE" ] && echo "  C engine: $C_ENGINE" || echo "  C engine: NOT INSTALLED"
            echo "  Python v1: $PYTHON_V1"
            echo "  Python TUI: $PYTHON_TUI"
            exit 0
            ;;
        --help|-h)
            banner
            echo "Usage: omega-zeroday [OPTIONS] <target_url>"
            echo ""
            echo "Options:"
            echo "  --engines, -e <list>  Comma-separated: recon,auth,race,ssrf,mass,smuggle,logic,crypto"
            echo "  --threads, -t <n>     Parallel threads (default: 20)"
            echo "  --timeout, -T <s>     Request timeout (default: 5)"
            echo "  --cookie, -c <str>    Cookie header value"
            echo "  --json, -j            Output as JSON"
            echo "  --quiet, -q           Suppress output"
            echo "  --no-menu, -n         Skip interactive menu, use C engine directly"
            echo "  --v1                  Use Python v1.0 engine"
            echo "  -h, --help            Show this help"
            echo "  -v, --version         Show version"
            echo ""
            echo "Examples:"
            echo "  omega-zeroday https://target.com                    # Interactive TUI"
            echo "  omega-zeroday https://target.com -n -e recon,auth   # Direct C engine"
            echo "  omega-zeroday https://target.com -j                 # JSON output"
            exit 0
            ;;
        --engines|-e) ENGINES="$2"; shift 2 ;;
        --threads|-t) THREADS="$2"; shift 2 ;;
        --timeout|-T) TIMEOUT="$2"; shift 2 ;;
        --cookie|-c) COOKIE="$2"; shift 2 ;;
        http*|https*|/*) TARGET="$1"; shift ;;
        *) shift ;;
    esac
done

# Build args for C engine (strip non-C-engine flags)
C_ARGS=""
[[ -n "$TARGET" ]] && C_ARGS="$C_ARGS $TARGET"
[[ -n "$ENGINES" ]] && C_ARGS="$C_ARGS --engines $ENGINES"
C_ARGS="$C_ARGS --timeout $TIMEOUT --threads $THREADS"
[[ -n "$COOKIE" ]] && C_ARGS="$C_ARGS --cookie $COOKIE"
$JSON && C_ARGS="$C_ARGS --json"
$QUIET && C_ARGS="$C_ARGS --quiet"

if [[ "$INTERACTIVE" == true ]] && [[ -n "$TARGET" ]]; then
    # Python TUI mode
    exec python3 "$PYTHON_TUI" $TARGET \
        ${ENGINES:+--engines "$ENGINES"} \
        --timeout "$TIMEOUT" \
        --threads "$THREADS" \
        ${COOKIE:+--cookie "$COOKIE"}
elif [[ -f "$C_ENGINE" ]]; then
    # Direct C engine mode
    exec $C_ENGINE $C_ARGS
elif [[ -f "$PYTHON_V1" ]]; then
    # Fallback to Python v1.0
    exec python3 "$PYTHON_V1" $C_ARGS
else
    echo -e "${RED}[ERROR] No engine available!${RESET}"
    echo "  C engine: $C_ENGINE"
    echo "  Python v1: $PYTHON_V1"
    exit 1
fi
