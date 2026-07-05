#!/usr/bin/env python3
"""
OMEGA-ZERODAY HUNTER v2.0 — Python Rich TUI
Beautiful terminal interface for the C engine.

Features:
- Dark hacker theme ASCII banner
- Interactive engine selection menu
- Live progress bars with ETA
- Live findings feed (real-time)
- Color-coded severity
- Phase indicators
- Activity heartbeat
"""

import sys
import os
import subprocess
import json
import time
import signal
import threading
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich.tree import Tree
    from rich import box
except ImportError:
    print("Installing required package: rich...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "--break-system-packages", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich.tree import Tree
    from rich import box

console = Console()

# ============================================================
# ASCII BANNER
# ============================================================

BANNER = """
[bold red]
  ██████╗ ██╗  ██╗██╗██╗       ██████╗  █████╗ ███╗   ██╗██████╗ ██╗     ██╗   ██╗███████╗
  ██╔═══██╗██║  ██║██║██║      ██╔═══██╗██╔══██╗████╗  ██║██╔══██╗██║     ██║   ██║██╔════╝
  ██║   ██║███████║██║██║      ██║   ██║███████║██╔██╗ ██║██║  ██║██║     ██║   ██║███████╗
  ██║▄▄ ██║██╔══██║██║██║      ██║   ██║██╔══██║██║╚██╗██║██║  ██║██║     ██║   ██║╚════██║
  ╚██████╔╝██║  ██║██║███████╗╚██████╔╝██║  ██║██║ ╚████║██████╔╝███████╗╚██████╔╝███████║
   ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
[/bold red]
[bold cyan]  🔒 Zero-Day Hunter v2.0 — C Engine + Python UI[/bold cyan]
[bold yellow]  ⚡ Blazing fast detection | 🎯 8 Real engines | 💀 No dummy code[/bold yellow]
[bold green]  👻 Ghost Killer Omega / Mirzacyberhub[/bold green]
"""

ENGINE_INFO = {
    "recon":      {"icon": "🔍", "name": "ReconSpider",    "desc": "Endpoint discovery & recon",          "color": "cyan"},
    "auth":       {"icon": "🔐", "name": "AuthBreaker",    "desc": "Authentication bypass detection",     "color": "red"},
    "race":       {"icon": "⚡", "name": "RaceHunter",     "desc": "Race condition (TOCTOU) detection",   "color": "yellow"},
    "ssrf":       {"icon": "🌐", "name": "SSRFOracle",    "desc": "Server-Side Request Forgery detection","color": "magenta"},
    "logic":      {"icon": "🧠", "name": "LogicBreaker",   "desc": "Business logic flaw detection",       "color": "blue"},
    "crypto":     {"icon": "🔒", "name": "CryptoOracle",   "desc": "Cryptographic weakness analysis",     "color": "green"},
    "massassign": {"icon": "🔎", "name": "MassAssign",     "desc": "Mass assignment detection",           "color": "bright_yellow"},
    "smuggle":    {"icon": "💀", "name": "SmuggleHunter",  "desc": "HTTP request smuggling detection",    "color": "bright_red"},
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold bright_red",
    "MEDIUM":   "bright_yellow",
    "LOW":      "yellow",
    "INFO":     "cyan",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

# ============================================================
# INTERACTIVE MENU
# ============================================================

def show_banner():
    console.print(BANNER)
    console.print()

def show_menu():
    """Show interactive engine selection menu"""
    table = Table(
        title="🎯 Select Detection Engines",
        box=box.ROUNDED,
        border_style="bright_cyan",
        title_style="bold bright_cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("#", style="bold bright_cyan", width=3)
    table.add_column("Engine", style="bold white", width=16)
    table.add_column("Description", style="dim white", width=45)
    table.add_column("Status", width=10)
    
    engines_list = list(ENGINE_INFO.keys())
    for i, eng_id in enumerate(engines_list, 1):
        info = ENGINE_INFO[eng_id]
        table.add_row(
            str(i),
            f"{info['icon']} {info['name']}",
            info['desc'],
            f"[green]ON[/green]"
        )
    
    console.print(table)
    console.print()
    console.print("[dim]  1-8: Toggle engine | A: All | Q: Quit[/dim]")
    console.print()

def get_user_selection():
    """Interactive engine selection"""
    selected = {k: True for k in ENGINE_INFO}
    
    while True:
        console.clear()
        show_banner()
        
        # Show current selection
        table = Table(box=box.SIMPLE, border_style="bright_cyan", show_header=True)
        table.add_column("#", width=3)
        table.add_column("Engine", width=20)
        table.add_column("Status", width=10)
        
        engines_list = list(ENGINE_INFO.keys())
        for i, eng_id in enumerate(engines_list, 1):
            info = ENGINE_INFO[eng_id]
            status = "[green]✅ ON[/green]" if selected[eng_id] else "[red]❌ OFF[/red]"
            table.add_row(str(i), f"{info['icon']} {info['name']}", status)
        
        console.print(table)
        console.print()
        
        # Show commands
        console.print("[bold cyan]Commands:[/bold cyan]")
        console.print("  [1-8] Toggle engine  |  [A] All ON  |  [N] None  |  [S] Start Scan  |  [Q] Quit")
        console.print()
        
        try:
            choice = input("  > ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            return None
        
        if choice == 'Q':
            return None
        elif choice == 'A':
            selected = {k: True for k in ENGINE_INFO}
        elif choice == 'N':
            selected = {k: False for k in ENGINE_INFO}
        elif choice == 'S':
            if not any(selected.values()):
                console.print("[red]  ❌ Select at least one engine![/red]")
                time.sleep(1)
                continue
            return [k for k, v in selected.items() if v]
        elif choice.isdigit() and 1 <= int(choice) <= len(engines_list):
            idx = int(choice) - 1
            eng_id = engines_list[idx]
            selected[eng_id] = not selected[eng_id]
        else:
            console.print("[yellow]  Invalid choice[/yellow]")
            time.sleep(0.5)

# ============================================================
# SCAN RUNNER
# ============================================================

def get_engine_binary():
    """Find the C engine binary"""
    script_dir = Path(__file__).parent
    build_dir = script_dir.parent / "engine" / "build"
    binary = build_dir / "omega-engine"
    
    if binary.exists():
        return str(binary)
    
    # Try to build it
    engine_dir = script_dir.parent / "engine"
    if (engine_dir / "Makefile").exists():
        console.print("[yellow]  ⚙️  Building C engine...[/yellow]")
        result = subprocess.run(
            ["make", "-C", str(engine_dir)],
            capture_output=True, text=True
        )
        if result.returncode == 0 and binary.exists():
            console.print("[green]  ✅ Build successful![/green]")
            return str(binary)
        else:
            console.print(f"[red]  ❌ Build failed:[/red]")
            console.print(f"[dim]{result.stderr}[/dim]")
    
    return None

def run_scan(target, selected_engines, threads=20, timeout=5, cookie=""):
    """Run the scan with live progress"""
    
    binary = get_engine_binary()
    if not binary:
        console.print("[bold red]  ❌ C engine not found! Run 'make' in engine/ directory first.[/bold red]")
        return
    
    # Build command
    engine_str = ",".join(selected_engines)
    cmd = [
        binary, target,
        "--engines", engine_str,
        "--threads", str(threads),
        "--timeout", str(timeout),
        "--json", "--markdown",
        "--output", str(Path(__file__).parent.parent / "results"),
    ]
    if cookie:
        cmd.extend(["--cookie", cookie])
    
    console.print()
    console.print(Panel(
        f"[bold white]Target:[/bold white] {target}\n"
        f"[bold white]Engines:[/bold white] {', '.join(selected_engines)}\n"
        f"[bold white]Threads:[/bold white] {threads}  |  [bold white]Timeout:[/bold white] {timeout}s",
        title="[bold bright_cyan]🔍 SCAN CONFIGURATION[/bold bright_cyan]",
        border_style="bright_cyan",
    ))
    console.print()
    
    start_time = time.time()
    findings = []
    current_engine = None
    current_progress = 0
    total_progress = 1
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        
        # Read stderr (progress and log output)
        stderr_lines = []
        
        with Live(console=console, refresh_per_second=4, transient=True) as live:
            while True:
                line = process.stderr.readline()
                if not line and process.poll() is not None:
                    break
                
                line = line.rstrip('\n')
                if not line:
                    continue
                
                stderr_lines.append(line)
                
                # Parse PROGRESS lines
                if line.startswith("PROGRESS|"):
                    parts = line.split("|")
                    if len(parts) >= 4:
                        current_engine = parts[1]
                        try:
                            current_progress = int(parts[2])
                            total_progress = int(parts[3])
                        except ValueError:
                            pass
                        detail = parts[4] if len(parts) > 4 else ""
                
                # Build live display
                elapsed = time.time() - start_time
                elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
                
                # Progress display
                display = Text()
                display.append(f"\n  ⏱️  Elapsed: {elapsed_str}\n\n", style="bold white")
                
                if current_engine:
                    info = ENGINE_INFO.get(current_engine, {})
                    icon = info.get("icon", "🔧")
                    name = info.get("name", current_engine)
                    
                    pct = (current_progress / total_progress * 100) if total_progress > 0 else 0
                    bar_len = 40
                    filled = int(pct / 100 * bar_len)
                    bar = "█" * filled + "░" * (bar_len - filled)
                    
                    display.append(f"  {icon} {name}\n", style="bold bright_cyan")
                    display.append(f"  [{bar}] {pct:.0f}% ({current_progress}/{total_progress})\n\n", style="bright_cyan")
                
                # Activity heartbeat
                dots = "." * (int(elapsed) % 4)
                display.append(f"  💓 Scanning{dots}\n", style="bold green")
                
                # Findings count
                display.append(f"\n  ⚡ Findings so far: {len(findings)}\n", style="bold yellow")
                
                live.update(Panel(display, title="[bold]OMEGA-ZERODAY SCAN[/bold]", border_style="bright_cyan"))
        
        # Process output
        stdout, stderr_all = process.communicate()
        
        # Parse findings from output
        for line in stderr_lines + (stdout or "").split('\n'):
            if "[CRITICAL]" in line or "[HIGH]" in line or "[MEDIUM]" in line or "[LOW]" in line:
                findings.append(line.strip())
        
        # Also try to load JSON results
        results_file = Path(__file__).parent.parent / "results" / "omega-findings.json"
        if results_file.exists():
            try:
                with open(results_file) as f:
                    data = json.load(f)
                    if "findings" in data:
                        findings = data["findings"]
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Final summary
        elapsed = time.time() - start_time
        console.print()
        console.print(Panel(
            f"[bold green]✅ SCAN COMPLETE[/bold green]\n\n"
            f"  ⏱️  Time: {int(elapsed // 60)}m {int(elapsed % 60)}s\n"
            f"  ⚡ Findings: {len(findings)}\n"
            f"  📁 Results: {Path(__file__).parent.parent / 'results'}",
            title="[bold bright_cyan]📊 RESULTS[/bold bright_cyan]",
            border_style="bright_cyan" if not findings else "bright_red",
        ))
        
        # Display findings table
        if findings:
            _display_findings(findings)
        else:
            console.print()
            console.print("[bold green]  🎉 No vulnerabilities found! Target appears secure.[/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[red]  ⚠️  Scan interrupted by user[/red]")
        if process:
            process.terminate()

def _display_findings(findings):
    """Display findings in a beautiful table"""
    console.print()
    
    table = Table(
        title="⚡ VULNERABILITY FINDINGS",
        box=box.ROUNDED,
        border_style="bright_red",
        title_style="bold bright_red",
    )
    table.add_column("#", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=50)
    table.add_column("URI", width=40)
    
    for i, f in enumerate(findings, 1):
        if isinstance(f, dict):
            sev = f.get("severity", "INFO")
            title = f.get("title", "Unknown")
            uri = f.get("uri", "N/A")
        else:
            # Parse string finding
            sev = "INFO"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if s in str(f):
                    sev = s
                    break
            title = str(f)[:50]
            uri = "N/A"
        
        sev_icon = SEVERITY_ICONS.get(sev, "⚪")
        sev_style = SEVERITY_COLORS.get(sev, "white")
        
        table.add_row(
            str(i),
            f"[{sev_style}]{sev_icon} {sev}[/{sev_style}]",
            title[:50],
            uri[:40],
        )
    
    console.print(table)

# ============================================================
# MAIN
# ============================================================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="OMEGA-ZERODAY HUNTER v2.0 — Beautiful TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Target URL (e.g., https://target.com)")
    parser.add_argument("--engines", "-e", help="Comma-separated engines")
    parser.add_argument("--threads", "-t", type=int, default=20, help="Threads (default: 20)")
    parser.add_argument("--timeout", "-T", type=int, default=5, help="Timeout in seconds (default: 5)")
    parser.add_argument("--cookie", "-c", default="", help="Authentication cookie")
    parser.add_argument("--no-menu", action="store_true", help="Skip interactive menu")
    parser.add_argument("--all", "-a", action="store_true", help="Enable all engines")
    
    args = parser.parse_args()
    
    show_banner()
    
    # Get target
    target = args.target
    if not target:
        try:
            target = input("  🎯 Enter target URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]  Bye! 👋[/dim]")
            return
        
        if not target:
            console.print("[red]  ❌ No target specified[/red]")
            return
        
        if not target.startswith("http"):
            target = "https://" + target
    
    # Get engine selection
    if args.engines:
        selected = [e.strip() for e in args.engines.split(",") if e.strip() in ENGINE_INFO]
    elif args.all:
        selected = list(ENGINE_INFO.keys())
    elif args.no_menu:
        selected = list(ENGINE_INFO.keys())
    else:
        selected = get_user_selection()
        if not selected:
            console.print("\n[dim]  Bye! 👋[/dim]")
            return
    
    console.print(f"\n  🎯 Target: [bold white]{target}[/bold white]")
    console.print(f"  ⚡ Engines: [bold cyan]{', '.join(selected)}[/bold cyan]")
    console.print()
    
    # Run scan
    run_scan(target, selected, args.threads, args.timeout, args.cookie)

if __name__ == "__main__":
    main()
