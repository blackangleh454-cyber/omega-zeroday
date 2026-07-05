# 🔥 OMEGA-ZERODAY Hunter v2.0.0

**Zero-day vulnerability discovery engine with 8 detection modules**

By **Ghost Killer Omega** | **Mirzacyberhub**

---

## 📋 Description

OMEGA-ZERODAY is an advanced zero-day vulnerability discovery tool designed for penetration testers, security researchers, and bug bounty hunters. Unlike other tools that simply wrap existing scanners, OMEGA-ZERODAY implements **real detection logic** from scratch.

## 🎯 Features

### 8 Specialized Detection Engines

| Engine | Description | Vulnerabilities Found |
|--------|-------------|----------------------|
| 🔍 **ReconSpider** | Endpoint discovery, sensitive files, API paths | Hidden endpoints, exposed files |
| 🔐 **AuthBreaker** | Authentication bypass, JWT analysis | Auth bypass, weak JWT |
| ⏱️ **RaceHunter** | Race condition (TOCTOU) detection | Double-execution, token reuse |
| 🌐 **SSRFOracle** | Server-Side Request Forgery | Internal network access |
| 📊 **MassAssign** | Mass assignment vulnerabilities | Hidden parameter injection |
| 🚀 **SmuggleHunter** | HTTP request smuggling | CL.TE, TE.CL, TE.TE |
| 💥 **LogicBreaker** | Business logic flaws | Price manipulation, workflow bypass |
| 🔐 **CryptoOracle** | Cryptographic weaknesses | Timing side-channels, weak algorithms |

### Additional Features

- **Exploit Chain Analysis** - Links related vulnerabilities into attack chains
- **C Engine** - High-performance C implementation for speed
- **Python Rich TUI** - Beautiful terminal interface with progress bars
- **JSON Output** - Machine-readable output for automation
- **Real Detection** - Original algorithms, not tool wrappers

## 🚀 Installation

### From Source

```bash
git clone https://github.com/mirzacyberhub/omega-zeroday
cd omega-zeroday
sudo dpkg -i omega-zeroday_2.0.0_amd64.deb
```

### Build from Source

```bash
# Install dependencies
sudo apt install build-essential libssl-dev python3 python3-rich python3-requests

# Build C engine
cd engine && make all

# Install
sudo make install
```

## 📖 Usage

### Basic Scan

```bash
# Scan with all engines
omega-engine https://target.com --engines all

# Quick recon
omega-engine https://target.com --engines recon

# Specific engines
omega-engine https://target.com --engines recon,auth,race
```

### Advanced Usage

```bash
# JSON output for automation
omega-engine https://target.com --engines all --json --quiet > results.json

# Custom settings
omega-engine https://target.com --threads 50 --timeout 20

# With authentication
omega-engine https://target.com --cookie "session=abc123"
```

### CLI Wrapper

```bash
# Interactive TUI
omega-zeroday https://target.com

# Direct C engine mode
omega-zeroday https://target.com --no-menu --engines all
```

## 📊 Output Example

```
══════════════════════════════════════════
  🎯 SCAN COMPLETE
══════════════════════════════════════════
  Duration:    103.4s
  Endpoints:   6
  Requests:    1000+

  🔴 CRITICAL: 2
  🟠 HIGH:     2
  📊 Total:    4
  ⛓️  Chains:   1

  FINDINGS:
  [CRITICAL] RACE_CONDITION - 3/5 requests succeeded
  [CRITICAL] SSRF - Internal network accessible
  [HIGH] TIMING_SIDE_CHANNEL - User enumeration possible
```

## 🛠️ Technical Details

### Architecture

```
┌─────────────────────────────────────────┐
│  OMEGA-ZERODAY v2.0                     │
├─────────────────────────────────────────┤
│  C Engine (omega-engine)     → Speed    │
│  Python TUI (omega_tui.py)  → Beauty    │
│  CLI Wrapper (omega-zeroday) → Routing  │
└─────────────────────────────────────────┘
```

### Detection Algorithms

- **RaceHunter**: Sends parallel bursts of requests and measures success rates
- **SSRFOracle**: Tests URL parameters with internal IP addresses
- **CryptoOracle**: Measures response timing differences for user enumeration
- **SmuggleHunter**: Tests HTTP header parsing inconsistencies

## 📁 File Structure

```
omega-zeroday/
├── engine/
│   ├── src/             # C source files
│   ├── include/         # Header files
│   └── Makefile         # Build system
├── ui/
│   └── omega_tui.py     # Python Rich TUI
├── debian/              # Debian packaging
├── omega-zeroday.sh     # CLI wrapper
├── omega_zeroday.py     # Python v1.0 engine
├── README.md            # This file
└── LICENSE              # GPLv3
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Kali Linux team for the amazing distribution
- Penetration testing community for inspiration
- Bug bounty hunters for real-world testing

## 📞 Contact

- **Author**: Mirzacyberhub
- **Email**: mirzacyberhub@proton.me
- **GitHub**: https://github.com/mirzacyberhub

---

**Built with 💀 by Ghost Killer Omega**
