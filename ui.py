from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import List, Dict, Any

console = Console()

class UI:
    @staticmethod
    def print_banner():
        banner = """
   __ __             __   _____      __                 
  / // /_  ____  ___/ /__/ ___/____  / /_  ___  ________ 
 / ,< / \/ / \/ _/  '</__ \/ _ \/ __ \/ _ \/ ___/ _ \
/_/|_/_/_/_/_/\__/_/\_\/____/ .___/_/ /_/\___/_/  \___/ 
                           /_/                           v1.0.0
        """
        console.print(f"[bold cyan]{banner}[/bold cyan]")
        console.print("[dim]KnockSphere - Async Subdomain Discovery & Threat Reconnaissance[/dim]\n")

    @staticmethod
    def display_results(results: List[Dict[str, Any]]):
        table = Table(title="KnockSphere Target Assets", show_lines=False)
        table.add_column("Subdomain", style="bold white")
        table.add_column("IPs", style="cyan")
        table.add_column("Source", style="magenta")
        table.add_column("HTTP", style="green")
        table.add_column("Title", style="dim white")
        table.add_column("TLS", style="yellow")

        for r in results:
            status_str = str(r.get("http_status")) if r.get("http_status") else "-"
            tls_str = r.get("tls_version") or "-"
            if r.get("tls_weak"):
                tls_str = f"[bold red]⚠️ {tls_str}[/bold red]"
                
            ips_str = ", ".join(r.get("ips", [])) if r.get("ips") else "-"
            
            table.add_row(
                r.get("subdomain"),
                ips_str,
                r.get("source"),
                status_str,
                (r.get("http_title") or "-")[:30],
                tls_str
            )

        console.print("\n")
        console.print(table)

    @staticmethod
    def display_summary(results: List[Dict[str, Any]], wildcard_detected: bool):
        total = len(results)
        weak_tls = sum(1 for r in results if r.get("tls_weak"))
        live_http = sum(1 for r in results if r.get("http_status"))

        summary_text = (
            f"Total Subdomains Found: [bold cyan]{total}[/bold cyan]\n"
            f"Active Web Services (HTTP/S): [bold green]{live_http}[/bold green]\n"
            f"Weak TLS Handshake Warnings: [bold red]{weak_tls}[/bold red]\n"
            f"Wildcard DNS Detected: [{'bold red' if wildcard_detected else 'bold green'}]{wildcard_detected}[/]"
        )
        console.print("\n", Panel(summary_text, title="[bold]Scan Summary[/bold]", expand=False))
