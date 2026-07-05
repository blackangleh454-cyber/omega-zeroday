# OMEGA-ZERODAY HUNTER v2.0

## ⚡ Overview
Production-grade 0-day vulnerability discovery engine with **C core** (speed) + **Python Rich TUI** (beauty). Detects real critical vulnerabilities across web apps, APIs, and infrastructure.

## 🎯 Quick Start

```bash
# Interactive TUI mode (default)
omega-zeroday https://target.com

# Direct C engine (fast, no menu)
omega-zeroday https://target.com --no-menu --engines recon,auth,crypto

# JSON output for automation
omega-zeroday https://target.com --no-menu --json

# Python v1.0 (single-file fallback)
omega-zeroday https://target.com --v1

# C engine directly
omega-engine https://target.com --engines all --threads 20
```

## 🔧 Architecture
```
omega-zeroday (shell wrapper)
├── C Engine (122KB binary)     ← /usr/local/bin/omega-engine
│   ├── recon.c                ← ReconSpider: HTML/JS/API/GraphQL parsing
│   ├── auth.c                 ← AuthBreaker: JWT confusion, header/path bypass
│   ├── race.c                 ← RaceHunter: TOCTOU, parallel burst, timing
│   ├── ssrf.c                 ← SSRFOracle: protocol smuggling, cloud metadata
│   ├── mass.c                 ← MassAssign: hidden params, content-type switching
│   ├── smuggle.c              ← SmuggleHunter: CL.TE, TE.CL, TE.TE
│   ├── logic.c                ← LogicBreaker: negative, overflow, type confusion
│   ├── crypto.c               ← CryptoOracle: ECB, weak hash, timing side-channel
│   ├── http.c                 ← Raw-socket HTTP/HTTPS client
│   ├── util.c                 ← Base64, hashing, thread pool, chain analysis
│   └── main.c                 ← CLI, scan orchestration, JSON output
├── Python Rich TUI            ← ui/omega_tui.py (interactive menu)
└── Python v1.0                ← omega_zeroday.py (standalone fallback)
```

## 🎯 8 Detection Engines

| Engine | What It Detects | Severity |
|--------|----------------|----------|
| **ReconSpider** | Endpoints, JS, APIs, GraphQL, sensitive files | INFO→HIGH |
| **AuthBreaker** | JWT alg:none, weak secrets, header bypass, path bypass | CRITICAL |
| **RaceHunter** | TOCTOU, double-exec, token/coupon reuse, state changes | HIGH |
| **SSRFOracle** | Redirect SSRF, cloud metadata, internal ports, proto smuggling | CRITICAL |
| **MassAssign** | Hidden params, content-type switching, method switching | CRITICAL |
| **SmuggleHunter** | CL.TE, TE.CL, TE.TE request smuggling | CRITICAL |
| **LogicBreaker** | Negative values, overflow, type confusion, rate bypass | CRITICAL |
| **CryptoOracle** | ECB mode, weak hash, timing side-channel, TLS issues | HIGH |

## 📊 CLI Options
```
--engines, -e <list>  Comma-separated: recon,auth,race,ssrf,mass,smuggle,logic,crypto
--threads, -t <n>     Parallel threads (default: 20)
--timeout, -T <s>     Request timeout (default: 5)
--cookie, -c <str>    Cookie header value
--json, -j            JSON output
--quiet, -q           Suppress progress
--no-menu, -n         Skip TUI, use C engine directly
--v1                  Use Python v1.0 engine
-h, --help            Help
-v, --version         Version
```

## 🏗️ Building from Source
```bash
cd ARSENAL/omega-zeroday/engine
make clean && make all
make install   # → /usr/local/bin/omega-engine
```

## 📦 Dependencies
- **C engine**: libssl-dev, libcrypto, pthreads
- **Python TUI**: rich (pip install rich)
- **Python v1.0**: requests, concurrent.futures

## 🔥 Key Features
- **Raw socket HTTP/HTTPS** — No libcurl dependency, full control
- **Chain analysis** — Links related findings into multi-step attack chains
- **CRITICAL-only reporting** — Only outputs high-confidence critical findings
- **JSON output** — Machine-readable for CI/CD integration
- **Thread pool** — Parallel endpoint testing with configurable concurrency
- **Signal handling** — Graceful shutdown on Ctrl+C
