#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  OMEGA-ZERODAY HUNTER v2.0 — Premium TUI Interface         ║
║  C Engine + Python Rich = Production-Grade Beauty           ║
║  Author: Ghost Killer Omega | By Mirzacyberhub              ║
╚══════════════════════════════════════════════════════════════╝

Interactive menu, live progress bars, ETA timers, findings feed.
"""

import os
import sys
import json
import time
import subprocess
import threading
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich.tree import Tree
    from rich import box
    from rich.markdown import Markdown
    from rich.style import Style
    from rich.highlighter import ReprHighlighter
except ImportError:
    print("Error: rich not installed. Run: pip install rich")
    sys.exit(1)

# ============================================================
# CONSTANTS
# ============================================================

VERSION = "2.0.0"
TOOL_NAME = "OMEGA-ZERODAY HUNTER"
ENGINE_PATH = None  # Auto-detected

ENGINES = {
    "recon":   {"name": "ReconSpider",      "icon": "🕷️",  "desc": "Endpoint discovery & API parsing"},
    "auth":    {"name": "AuthBreaker",       "icon": "🔓",  "desc": "JWT bypass, weak secrets, auth bypass"},
    "race":    {"name": "RaceHunter",        "icon": "⚡",  "desc": "Race condition & double-exec"},
    "ssrf":    {"name": "SSRFOracle",        "icon": "🌐",  "desc": "SSRF, cloud metadata, redirect"},
    "mass":    {"name": "MassAssign",        "icon": "📦",  "desc": "Hidden params & content-type"},
    "smuggle": {"name": "SmuggleHunter",     "icon": "🚂",  "desc": "HTTP request smuggling"},
    "logic":   {"name": "LogicBreaker",      "icon": "🧠",  "desc": "Negative values, overflow, type confusion"},
    "crypto":  {"name": "CryptoOracle",      "icon": "🔐",  "desc": "ECB, timing, weak hash, TLS"},
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "white",
    "INFO": "cyan",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "⚪",
    "INFO": "ℹ️",
}

console = Console()

# ============================================================
# ENGINE PATH DETECTION
# ============================================================

def find_engine() -> str:
    """Find the omega-engine binary."""
    global ENGINE_PATH
    
    candidates = [
        Path(__file__).parent / "engine" / "omega-engine",
        Path("/usr/local/bin/omega-engine"),
        Path(__file__).parent / "omega-engine",
    ]
    
    for p in candidates:
        if p.exists() and os.access(str(p), os.X_OK):
            ENGINE_PATH = str(p)
            return ENGINE_PATH
    
    return None

def find_v1_script() -> str:
    """Find the v1.0 Python script as fallback."""
    candidates = [
        Path(__file__).parent / "omega_zeroday.py",
        Path("/usr/local/bin/omega-zeroday"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None

# ============================================================
# ASCII BANNER
# ============================================================

def print_banner():
    banner = """[bold red]  ██████  ██ ███████ ████████  ██████   ██████  ██████  ██████  ███████[/]
[bold red]  ██   ██ ██ ██         ██    ██    ██ ██      ██    ██ ██   ██ ██     [/]
[bold red]  ██████  ██ ███████    ██    ██    ██ ██      ██    ██ ██████  █████  [/]
[bold red]  ██   ██ ██      ██    ██    ██    ██ ██      ██    ██ ██   ██ ██     [/]
[bold red]  ██████  ██ ███████    ██     ██████   ██████  ██████  ██   ██ ███████[/]
[bold yellow]       ⚡ Z E R O D A Y   H U N T E R   v{v} ⚡[/]
[white]       Real Vulnerability Discovery Engine[/]
[white]       By Ghost Killer Omega | C Engine + Python UI[/]"""
    
    console.print(banner.format(v=VERSION))
    console.print()

# ============================================================
# INTERACTIVE MENU
# ============================================================

def show_menu() -> Dict:
    """Interactive menu for scan configuration."""
    print_banner()
    
    # Target input
    console.print("[bold white]  ── TARGET CONFIGURATION ──[/]\n")
    target = console.input("  [cyan]► Target URL:[/] ")
    if not target.startswith("http"):
        target = "https://" + target
    
    console.print()
    
    # Engine selection
    console.print("[bold white]  ── ENGINE SELECTION ──[/]\n")
    console.print("  [dim]Leave empty for ALL engines[/]\n")
    
    table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE_HEAVY, padding=(0, 2))
    table.add_column("#", style="dim", width=3)
    table.add_column("Engine", style="bold white", width=14)
    table.add_column("Icon", width=3)
    table.add_column("Description", style="dim", width=40)
    table.add_column("Select", width=6)
    
    engine_keys = list(ENGINES.keys())
    for i, (key, info) in enumerate(ENGINES.items()):
        table.add_row(
            str(i + 1),
            info["name"],
            info["icon"],
            info["desc"],
            "[✓]"
        )
    
    console.print(table)
    console.print()
    
    engines_input = console.input("  [cyan]► Engines (comma-separated, or Enter for all):[/] ")
    
    if engines_input.strip():
        selected = [e.strip() for e in engines_input.split(",")]
        # Validate
        valid = [e for e in selected if e in ENGINES]
        if not valid:
            console.print("  [yellow]⚠ Invalid engines, using all[/]")
            valid = list(ENGINES.keys())
    else:
        valid = list(ENGINES.keys())
    
    console.print()
    
    # Options
    console.print("[bold white]  ── SCAN OPTIONS ──[/]\n")
    
    cookie = console.input("  [cyan]► Cookie (Enter to skip):[/] ")
    threads_str = console.input("  [cyan]► Threads [20]:[/] ") or "20"
    timeout_str = console.input("  [cyan]► Timeout (s) [10]:[/] ") or "10"
    json_out = console.input("  [cyan]► JSON output? (y/N):[/] ").lower() == "y"
    
    return {
        "target": target,
        "engines": valid,
        "cookie": cookie,
        "threads": int(threads_str),
        "timeout": int(timeout_str),
        "json_output": json_out,
    }

def show_quick_scan():
    """Quick scan with minimal input."""
    print_banner()
    
    target = console.input("  [cyan]► Target URL:[/] ")
    if not target.startswith("http"):
        target = "https://" + target
    
    return {
        "target": target,
        "engines": list(ENGINES.keys()),
        "cookie": "",
        "threads": 20,
        "timeout": 10,
        "json_output": False,
    }

# ============================================================
# ENGINE BUILD
# ============================================================

def build_engine() -> bool:
    """Build the C engine if needed."""
    engine_dir = Path(__file__).parent / "engine"
    engine_bin = engine_dir / "omega-engine"
    
    if engine_bin.exists():
        return True
    
    console.print("  [yellow]⚠ C engine not found. Building...[/]")
    
    try:
        result = subprocess.run(
            ["make", "-C", str(engine_dir), "all"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            console.print("  [green]✅ Build successful![/]")
            return True
        else:
            console.print(f"  [red]❌ Build failed:[/]\n{result.stderr}")
            return False
    except Exception as e:
        console.print(f"  [red]❌ Build error: {e}[/]")
        return False

# ============================================================
# SCAN EXECUTION (with live progress)
# ============================================================

def run_scan(config: Dict) -> Optional[Dict]:
    """Run the scan with live progress display."""
    
    engine_bin = find_engine()
    v1_script = find_v1_script()
    
    if engine_bin:
        return run_scan_c_engine(config, engine_bin)
    elif v1_script:
        console.print("  [yellow]⚠ C engine not found, using v1.0 Python engine[/]")
        return run_scan_python(config, v1_script)
    else:
        # Try building
        if build_engine():
            engine_bin = find_engine()
            if engine_bin:
                return run_scan_c_engine(config, engine_bin)
        
        console.print("  [red]❌ No engine found! Please build first.[/]")
        console.print("  [dim]  cd engine/ && make all[/]")
        return None

def run_scan_c_engine(config: Dict, engine_bin: str) -> Optional[Dict]:
    """Run the C engine with Rich progress display."""
    
    cmd = [engine_bin, config["target"], "--json"]
    cmd.extend(["--engines", ",".join(config["engines"])])
    cmd.extend(["--threads", str(config["threads"])])
    cmd.extend(["--timeout", str(config["timeout"])])
    if config["cookie"]:
        cmd.extend(["--cookie", config["cookie"]])
    
    start_time = time.time()
    
    # Run with progress animation
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        
        # Main scan task
        task = progress.add_task(
            f"[cyan]⚡ Scanning {config['target']}",
            total=100
        )
        
        # Engine tasks
        engine_tasks = {}
        for eng_key in config["engines"]:
            info = ENGINES[eng_key]
            et = progress.add_task(
                f"  {info['icon']} {info['name']}",
                total=None  # Indeterminate
            )
            engine_tasks[eng_key] = et
        
        # Run the actual scan
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3600
            )
            
            # Animate completion
            elapsed = time.time() - start_time
            total_est = elapsed * 1.0  # Already done
            
            # Complete all tasks
            progress.update(task, completed=100)
            for et in engine_tasks.values():
                if not progress.tasks[et].finished:
                    progress.stop_task(et)
        
        except subprocess.TimeoutExpired:
            console.print("\n  [red]❌ Scan timed out![/]")
            return None
        except KeyboardInterrupt:
            console.print("\n  [yellow]⚠ Scan interrupted[/]")
            return None
    
    duration = time.time() - start_time
    
    # Parse JSON output
    try:
        scan_result = json.loads(result.stdout)
        scan_result["_duration"] = duration
        scan_result["_returncode"] = result.returncode
        return scan_result
    except json.JSONDecodeError:
        console.print(f"  [red]❌ Failed to parse engine output[/]")
        if result.stderr:
            console.print(f"  [dim]{result.stderr[:500]}[/]")
        return None

def run_scan_python(config: Dict, script: str) -> Optional[Dict]:
    """Fallback to v1.0 Python engine."""
    
    cmd = [sys.executable, script, config["target"]]
    cmd.extend(["--engines", ",".join(config["engines"])])
    if config["cookie"]:
        cmd.extend(["--cookie", config["cookie"]])
    cmd.extend(["--threads", str(config["threads"])])
    cmd.extend(["--timeout", str(config["timeout"])])
    
    start_time = time.time()
    
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold white]{task.description}[/]"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]⚡ Scanning {config['target']}", total=100)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            progress.update(task, completed=100)
        except Exception as e:
            console.print(f"\n  [red]❌ {e}[/]")
            return None
    
    duration = time.time() - start_time
    
    # Try to parse JSON from output
    try:
        scan_result = json.loads(result.stdout)
        scan_result["_duration"] = duration
        return scan_result
    except:
        # v1.0 might not output JSON, parse text
        return {
            "target": config["target"],
            "_duration": duration,
            "_raw_output": result.stdout,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "total": 0},
        }

# ============================================================
# RESULTS DISPLAY
# ============================================================

def display_results(result: Dict):
    """Display scan results with beautiful Rich formatting."""
    
    console.print()
    
    # ── Scan Summary Panel ──
    duration = result.get("_duration", 0)
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    chains = result.get("chains_detail", result.get("chains", []))
    
    # Summary grid
    summary_table = Table(show_header=False, box=None, padding=(0, 3))
    summary_table.add_column("Metric", style="dim")
    summary_table.add_column("Value", style="bold")
    
    summary_table.add_row("🎯 Target", result.get("target", "Unknown"))
    summary_table.add_row("⏱️ Duration", f"{duration:.1f}s")
    summary_table.add_row("📡 Endpoints", str(result.get("endpoints", 0)))
    summary_table.add_row("🔢 Requests", str(result.get("requests", 0)))
    summary_table.add_row("🔗 Chains", str(len(chains) if isinstance(chains, list) else chains))
    summary_table.add_row("📊 Total Findings", str(summary.get("total", len(findings))))
    
    console.print(Panel(
        summary_table,
        title="[bold white]SCAN SUMMARY[/]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    
    # ── Severity Breakdown ──
    sev_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    
    sev_table.add_row("[bold red]🔴 CRITICAL[/]", f"[bold red]{crit}[/]")
    sev_table.add_row("[bold yellow]🟠 HIGH[/]", f"[bold yellow]{high}[/]")
    sev_table.add_row("[yellow]🟡 MEDIUM[/]", f"[yellow]{med}[/]")
    sev_table.add_row("[white]📊 TOTAL[/]", f"[bold white]{len(findings)}[/]")
    
    console.print(Panel(
        sev_table,
        title="[bold red]SEVERITY BREAKDOWN[/]",
        border_style="red" if crit > 0 else ("yellow" if high > 0 else "dim"),
        box=box.ROUNDED,
    ))
    
    console.print()
    
    # ── Findings Table ──
    if findings:
        console.print("[bold white]═══════════════════════════════════════════[/]")
        console.print("[bold white]  🔍 FINDINGS[/]")
        console.print("[bold white]═══════════════════════════════════════════[/]\n")
        
        ftable = Table(
            box=box.ROUNDED,
            show_lines=True,
            header_style="bold cyan",
            title="Vulnerability Findings",
            title_style="bold white",
            padding=(0, 1),
        )
        ftable.add_column("#", style="dim", width=3)
        ftable.add_column("Severity", width=10)
        ftable.add_column("Type", style="bold white", width=22)
        ftable.add_column("CVSS", justify="center", width=5)
        ftable.add_column("Confidence", justify="center", width=10)
        ftable.add_column("Description", max_width=50)
        ftable.add_column("Engine", style="dim", width=10)
        
        for i, f in enumerate(findings):
            sev = f.get("severity", "INFO")
            ftable.add_row(
                str(i + 1),
                f"[{SEVERITY_COLORS.get(sev, 'white')}]{SEVERITY_ICONS.get(sev, '')} {sev}[/]",
                f.get("type", "Unknown"),
                f"[bold]{f.get('cvss', 0):.1f}[/]",
                f"{f.get('confidence', 0)*100:.0f}%",
                f.get("description", "")[:50],
                f.get("engine", ""),
            )
        
        console.print(ftable)
        
        # ── Detailed Findings ──
        console.print()
        for i, f in enumerate(findings):
            sev = f.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "white")
            
            detail = Table(show_header=False, box=None, padding=(0, 2))
            detail.add_column("Key", style="dim", width=12)
            detail.add_column("Value")
            
            detail.add_row("URL", f.get("url", ""))
            detail.add_row("Description", f.get("description", ""))
            detail.add_row("Evidence", f.get("evidence", ""))
            detail.add_row("CWE", f.get("cwe", ""))
            detail.add_row("Engine", f.get("engine", ""))
            
            console.print(Panel(
                detail,
                title=f"[{color}]{SEVERITY_ICONS.get(sev, '')} {sev}: {f.get('type', 'Unknown')}[/]",
                border_style=color.split(" ")[-1] if " " in color else color,
                box=box.ROUNDED,
            ))
    else:
        console.print("[green]  ✅ No vulnerabilities found — target appears secure![/]")
    
    # ── Exploit Chains ──
    if chains and isinstance(chains, list) and len(chains) > 0:
        console.print()
        console.print("[bold magenta]═══════════════════════════════════════════[/]")
        console.print("[bold magenta]  ⛓️ EXPLOIT CHAINS[/]")
        console.print("[bold magenta]═══════════════════════════════════════════[/]\n")
        
        for i, c in enumerate(chains):
            console.print(Panel(
                f"[white]{c.get('description', '')}[/]\n\n"
                f"  [dim]Steps: {c.get('steps', 0)} | CVSS: {c.get('cvss', 0):.1f} | Severity: {c.get('severity', 'CRITICAL')}[/]",
                title=f"[bold magenta]🔗 Chain {i+1}[/]",
                border_style="magenta",
                box=box.DOUBLE,
            ))
    
    # ── Export option ──
    if findings:
        console.print()
        save = console.input("  [cyan]► Save report? (Enter filename or N):[/] ")
        if save.strip() and save.strip().upper() != "N":
            save_report(result, save.strip())

def save_report(result: Dict, filename: str):
    """Save report to file."""
    report_dir = Path.home() / ".qwenpaw" / "workspaces" / "default" / "memory" / "reports" / "omega-zeroday"
    report_dir.mkdir(parents=True, exist_ok=True)
    
    if not filename.endswith(".json"):
        filename += ".json"
    
    filepath = report_dir / filename
    
    with open(filepath, "w") as f:
        json.dump(result, f, indent=2)
    
    console.print(f"  [green]✅ Report saved: {filepath}[/]")

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} v{VERSION}")
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("--engines", help="Comma-separated engine list")
    parser.add_argument("--cookie", help="Cookie header")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--quick", action="store_true", help="Quick scan (minimal prompts)")
    parser.add_argument("--no-menu", action="store_true", help="Skip interactive menu")
    parser.add_argument("--build", action="store_true", help="Build C engine only")
    args = parser.parse_args()
    
    # Build only mode
    if args.build:
        print_banner()
        build_engine()
        return
    
    # Determine scan config
    if args.target:
        # CLI mode
        engines = args.engines.split(",") if args.engines else list(ENGINES.keys())
        config = {
            "target": args.target,
            "engines": engines,
            "cookie": args.cookie or "",
            "threads": args.threads,
            "timeout": args.timeout,
            "json_output": args.json,
        }
    elif args.no_menu:
        config = show_quick_scan()
    else:
        # Interactive menu
        config = show_menu()
    
    # Run scan
    console.print()
    with console.status("[bold cyan]⚡ Initializing Omega-Zeroday engine...", spinner="dots"):
        time.sleep(0.5)  # Brief pause for visual effect
    
    result = run_scan(config)
    
    if result:
        display_results(result)
    else:
        console.print("\n  [red]❌ Scan failed![/]")
        sys.exit(1)

if __name__ == "__main__":
    main()
