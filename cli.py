import argparse
import asyncio
import sys
import os
import aiohttp

from knocksphere.config import Config
from knocksphere.db import DatabaseManager
from knocksphere.ui import UI, console
from knocksphere.discovery.passive import PassiveScraper
from knocksphere.discovery.bruteforce import AsyncBruteforcer
from knocksphere.discovery.wildcard import WildcardDetector
from knocksphere.probing.http import HTTPProber
from knocksphere.reporting.html import HTMLReporter

async def main_async(args):
    config = Config.load(args.config)
    
    if args.concurrency:
        config.concurrency = args.concurrency
    if args.timeout:
        config.timeout = args.timeout

    db = DatabaseManager(args.db)

    # 1. Passive Sources Diagnostic Mode
    if args.test_passive:
        console.print("[bold cyan][*] Testing Passive Intelligence Sources...[/bold cyan]\n")
        results = await PassiveScraper.test_sources(config)
        for name, status, msg in results:
            symbol = "[bold green]✔[/bold green]" if status else "[bold red]✘[/bold red]"
            console.print(f"  {symbol} [bold]{name}:[/bold] {msg}")
        return

    # 2. Database Commands
    if args.list_scans:
        scans = db.list_scans()
        console.print("[bold cyan]Historical KnockSphere Scans:[/bold cyan]\n")
        for s in scans:
            console.print(f"  [bold]ID {s['id']}:[/bold] {s['domain']} | Discovered: {s['total_discovered']} | Date: {s['created_at']}")
        return

    if args.delete_scan:
        if db.delete_scan(args.delete_scan):
            console.print(f"[bold green][✔] Successfully deleted scan ID {args.delete_scan}[/bold green]")
        else:
            console.print(f"[bold red][✘] Scan ID {args.delete_scan} not found.[/bold red]")
        return

    if args.search:
        results = db.search_subdomains(args.search)
        console.print(f"[bold cyan]Search results for '{args.search}':[/bold cyan]")
        UI.display_results(results)
        return

    if args.diagnose_host:
        console.print(f"[bold cyan][*] Running deep HTTP & TLS diagnostic on {args.diagnose_host}...[/bold cyan]\n")
        headers = {"User-Agent": config.user_agent}
        async with aiohttp.ClientSession(headers=headers) as session:
            prober = HTTPProber(session, timeout=config.timeout)
            res = await prober.probe(args.diagnose_host)
            for k, v in res.items():
                console.print(f"  [bold]{k}:[/bold] {v}")
        return

    if not args.domain:
        console.print("[bold red][!] Target domain (-d/--domain) required.[/bold red]")
        sys.exit(1)

    UI.print_banner()

    domain = args.domain.lower()
    console.print(f"[*] Target Domain: [bold cyan]{domain}[/bold cyan]")

    # 3. Wildcard Check
    console.print("[*] Inspecting Wildcard DNS posture...")
    wildcard_detector = WildcardDetector(domain, config.dns_servers, timeout=config.timeout)
    is_wildcard, wildcard_ips = await wildcard_detector.detect()
    
    if is_wildcard:
        console.print(f"  [bold yellow]⚠️ Wildcard DNS Active![/bold yellow] Filtered IPs: {', '.join(wildcard_ips)}")
    else:
        console.print("  [green]✔ No Wildcard DNS detected.[/green]")

    discovered_map = {}

    headers = {"User-Agent": config.user_agent}
    async with aiohttp.ClientSession(headers=headers) as session:
        # 4. Passive Gathering
        console.print("\n[*] Fetching Passive Feeds...")
        scraper = PassiveScraper(domain, config, session)
        passive_results = await scraper.run_all()
        
        for source, subdomains in passive_results.items():
            console.print(f"  [dim]↳ {source}: {len(subdomains)} subdomains[/dim]")
            for sub in subdomains:
                discovered_map[sub] = {"subdomain": sub, "ips": [], "source": source, "is_wildcard": False}

        # 5. Wordlist Bruteforcing
        if args.wordlist:
            if not os.path.exists(args.wordlist):
                console.print(f"[bold red][!] Wordlist path missing: {args.wordlist}[/bold red]")
            else:
                with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]

                console.print(f"\n[*] Executing Async Bruteforce ({len(words)} entries)...")
                bruteforcer = AsyncBruteforcer(
                    domain=domain,
                    wordlist=words,
                    resolvers=config.dns_servers,
                    concurrency=config.concurrency,
                    timeout=config.timeout,
                    wildcard_ips=wildcard_ips if is_wildcard else None
                )

                from rich.progress import Progress
                with Progress() as progress:
                    task_id = progress.add_task("[cyan]Bruteforcing...", total=len(words))
                    
                    def update_progress():
                        progress.update(task_id, advance=1)

                    bf_results = await bruteforcer.run(progress_callback=update_progress)
                    
                for r in bf_results:
                    sub = r["subdomain"]
                    if sub in discovered_map:
                        discovered_map[sub]["ips"] = list(set(discovered_map[sub]["ips"] + r["ips"]))
                        discovered_map[sub]["source"] += ", bruteforce"
                    else:
                        discovered_map[sub] = r

        # 6. HTTP and TLS Audit
        results_list = list(discovered_map.values())
        if results_list:
            console.print(f"\n[*] Auditing HTTP/HTTPS & TLS state for {len(results_list)} discovered assets...")
            prober = HTTPProber(session, timeout=config.timeout)
            
            from rich.progress import Progress
            with Progress() as progress:
                probe_task = progress.add_task("[green]Probing Assets...", total=len(results_list))
                
                async def probe_worker(item):
                    p_info = await prober.probe(item["subdomain"])
                    item.update(p_info)
                    progress.update(probe_task, advance=1)

                await asyncio.gather(*[probe_worker(item) for item in results_list])

    # 7. Database Persistence
    scan_id = db.create_scan(domain, is_wildcard)
    db.save_results(scan_id, results_list)
    console.print(f"\n[bold green][✔] Results persisted to SQLite (Scan ID: {scan_id})[/bold green]")

    UI.display_results(results_list)
    UI.display_summary(results_list, is_wildcard)

    # 8. Report Generation
    if args.html_report:
        HTMLReporter.generate(domain, results_list, args.html_report)
        console.print(f"\n[bold green][✔] HTML Report exported to {args.html_report}[/bold green]")

    if args.csv_report:
        db.export_csv(scan_id, args.csv_report)
        console.print(f"[bold green][✔] CSV Report exported to {args.csv_report}[/bold green]")

def main():
    parser = argparse.ArgumentParser(description="KnockSphere - Async Subdomain Discovery & Intelligence Tool")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-c", "--config", help="Path to custom config.yaml")
    parser.add_argument("--concurrency", type=int, help="Max async concurrency")
    parser.add_argument("--timeout", type=float, help="Network timeout in seconds")
    parser.add_argument("--db", default="knocksphere.db", help="SQLite database file")
    
    parser.add_argument("--test-passive", action="store_true", help="Test health of passive sources")
    parser.add_argument("--diagnose-host", help="Run deep HTTP/TLS check on a single host")
    
    parser.add_argument("--list-scans", action="store_true", help="List scans in local DB")
    parser.add_argument("--search", help="Search subdomains in database")
    parser.add_argument("--delete-scan", type=int, help="Delete scan by ID")

    parser.add_argument("--html-report", help="Output path for HTML report")
    parser.add_argument("--csv-report", help="Output path for CSV report")

    args = parser.parse_args()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrupted by user.[/bold red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
