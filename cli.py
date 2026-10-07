#!/usr/bin/env python3
"""
VirusTotal-Style Phishing Link Scanner CLI.
Renders detection summary, vendor matrix, and threat indicators in terminal using Rich.
"""
import os
import sys
import argparse

# Force UTF-8 on Windows terminals to prevent cp1252 charmap encoding errors
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich import box

from detector.analyzer import PhishingAnalyzer, ScanResult

console = Console(force_terminal=True, legacy_windows=False)


def print_banner():
    banner = Text()
    banner.append(" PHISHING DETECTOR ", style="bold white on blue")
    banner.append("  URL RISK INTELLIGENCE SCANNER\n", style="bold cyan")
    banner.append("  Multi-Engine Security Consensus & Lexical Threat Heuristics", style="dim")
    console.print(Panel(banner, border_style="blue", box=box.ROUNDED))


def format_risk_badge(result: ScanResult) -> Panel:
    score = result.risk_score
    level = result.risk_level
    stats = result.stats

    if level == "MALICIOUS":
        color = "bold red"
        badge = "[!] MALICIOUS / PHISHING"
        border = "red"
        symbol = "X"
    elif level == "SUSPICIOUS":
        color = "bold yellow"
        badge = "[?] SUSPICIOUS"
        border = "yellow"
        symbol = "!"
    elif level == "LOW RISK":
        color = "bold yellow"
        badge = "[*] LOW RISK"
        border = "yellow"
        symbol = "!"
    else:
        color = "bold green"
        badge = "[+] CLEAN & SAFE"
        border = "green"
        symbol = "+"

    content = Text()
    content.append(f"\n   [{symbol}] DETECTION RATIO : ", style="bold")
    content.append(f"{result.detection_ratio}\n", style=color)
    content.append(f"   VERDICT         : ", style="bold")
    content.append(f"{badge}\n", style=color)
    content.append(f"   RISK SCORE      : ", style="bold")
    content.append(f"{score}% ", style=color)

    # Meter bar
    bar_len = 30
    filled_len = int((score / 100.0) * bar_len)
    meter = "█" * filled_len + "░" * (bar_len - filled_len)
    content.append(f"[{meter}]\n\n", style=color)

    content.append(f"   Breakdown:  ", style="dim")
    content.append(f"Malicious: {stats.get('malicious', 0)}  ", style="red bold")
    content.append(f"Suspicious: {stats.get('suspicious', 0)}  ", style="yellow bold")
    content.append(f"Harmless: {stats.get('harmless', 0)}  ", style="green bold")
    content.append(f"Undetected: {stats.get('undetected', 0)}\n", style="dim")

    return Panel(content, title="[bold]Phishing Threat Intelligence Consensus[/bold]", border_style=border, box=box.ROUNDED)


def display_results(result: ScanResult, show_all_vendors: bool = False):
    console.print()
    
    # URL metadata panel
    meta_table = Table.grid(padding=(0, 2))
    meta_table.add_column(style="bold cyan")
    meta_table.add_column()

    meta_table.add_row("Scanned URL:", result.url)
    meta_table.add_row("Target Host:", result.hostname)
    meta_table.add_row("Data Source:", result.source)
    if result.brand_spoofed:
        meta_table.add_row("Brand Impersonated:", f"[bold red]{result.brand_spoofed.upper()}[/bold red]")

    console.print(Panel(meta_table, title="[bold]Target URL Properties[/bold]", border_style="cyan", box=box.ROUNDED))

    # Consensus Badge
    console.print(format_risk_badge(result))

    # Heuristic Threat Indicators Table
    ind_table = Table(title="Observed Threat Indicators & Heuristics", box=box.SIMPLE_HEAVY)
    ind_table.add_column("#", style="dim", width=4)
    ind_table.add_column("Security Finding / Indicator", style="bold")
    ind_table.add_column("Severity", justify="center")

    for i, ind in enumerate(result.indicators, 1):
        if result.risk_level == "CLEAN":
            sev = "[green]SAFE[/green]"
        elif "brand" in ind.lower() or "punycode" in ind.lower() or "ip address" in ind.lower():
            sev = "[bold red]HIGH[/bold red]"
        elif "keyword" in ind.lower() or "tld" in ind.lower() or "bypass" in ind.lower():
            sev = "[bold yellow]MEDIUM[/bold yellow]"
        else:
            sev = "[cyan]INFO[/cyan]"
        ind_table.add_row(str(i), ind, sev)

    console.print(ind_table)
    console.print()

    # Vendor Matrix Table
    vendor_table = Table(
        title="Security Vendor Detections (Multi-Engine Matrix)",
        box=box.MINIMAL_DOUBLE_HEAD,
        show_lines=False
    )
    vendor_table.add_column("Security Vendor", style="bold")
    vendor_table.add_column("Status / Category", justify="center")
    vendor_table.add_column("Engine Result", style="dim")
    vendor_table.add_column("Detection Method", style="dim", justify="right")

    items = list(result.vendor_results.items())
    
    # Show flagged engines first, then clean engines
    flagged_items = [item for item in items if item[1]["category"] in ("malicious", "suspicious")]
    clean_items = [item for item in items if item[1]["category"] not in ("malicious", "suspicious")]
    
    sorted_items = flagged_items + clean_items

    # If there are many vendors and not show_all, show flagged + top clean ones
    display_items = sorted_items if show_all_vendors else (flagged_items + clean_items[:max(10, 15 - len(flagged_items))])

    for vendor_name, data in display_items:
        cat = data.get("category", "undetected")
        res = data.get("result", "clean")
        method = data.get("method", "heuristic")

        if cat == "malicious":
            cat_text = "[bold red]Malicious[/bold red]"
            res_text = f"[red]{res}[/red]"
        elif cat == "suspicious":
            cat_text = "[bold yellow]Suspicious[/bold yellow]"
            res_text = f"[yellow]{res}[/yellow]"
        elif cat == "harmless":
            cat_text = "[bold green]Clean[/bold green]"
            res_text = "[green]Clean[/green]"
        else:
            cat_text = "[dim]Undetected[/dim]"
            res_text = "[dim]Unrated[/dim]"

        vendor_table.add_row(vendor_name, cat_text, res_text, method)

    console.print(vendor_table)

    if not show_all_vendors and len(sorted_items) > len(display_items):
        remaining = len(sorted_items) - len(display_items)
        console.print(f"[dim]... and {remaining} more security vendors rated Clean/Undetected (Use --all to view all 72 vendors)[/dim]\n")


def scan_single_url(analyzer: PhishingAnalyzer, url: str, show_all: bool = False):
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Analyzing URL features & querying vendor engines...[/bold cyan]"),
        transient=True
    ) as progress:
        progress.add_task("scan", total=None)
        result = analyzer.scan(url)

    display_results(result, show_all_vendors=show_all)


def interactive_mode(analyzer: PhishingAnalyzer):
    print_banner()
    console.print("[cyan]Enter URLs to scan (type [bold red]'exit'[/bold red] or [bold red]'q'[/bold red] to quit):[/cyan]\n")

    while True:
        try:
            url_input = console.input("[bold yellow]Enter URL to scan > [/bold yellow]").strip()
            if not url_input:
                continue
            if url_input.lower() in ("exit", "quit", "q"):
                console.print("[green]Goodbye![/green]")
                break

            scan_single_url(analyzer, url_input, show_all=False)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[green]Session terminated.[/green]")
            break


def main():
    parser = argparse.ArgumentParser(description="VirusTotal Phishing URL Detector & Risk Analyzer")
    parser.add_argument("url", nargs="?", help="Target URL to scan")
    parser.add_argument("--api-key", default=os.getenv("VIRUSTOTAL_API_KEY"), help="Optional VirusTotal API v3 Key")
    parser.add_argument("--all", action="store_true", help="Display all 72 security vendors in output table")
    args = parser.parse_args()

    analyzer = PhishingAnalyzer(vt_api_key=args.api_key)

    if args.url:
        print_banner()
        scan_single_url(analyzer, args.url, show_all=args.all)
    else:
        interactive_mode(analyzer)


if __name__ == "__main__":
    main()
