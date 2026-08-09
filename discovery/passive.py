import asyncio
import aiohttp
import re
from typing import Set, Dict, List, Tuple

class PassiveScraper:
    def __init__(self, domain: str, config, session: aiohttp.ClientSession):
        self.domain = domain.lower()
        self.config = config
        self.session = session

    async def crt_sh(self) -> Set[str]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with self.session.get(url, timeout=self.config.timeout * 2) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    subdomains = set()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(self.domain) and "*" not in name:
                                subdomains.add(name)
                    return subdomains
        except Exception:
            pass
        return set()

    async def hackertarget(self) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with self.session.get(url, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    subdomains = set()
                    for line in text.splitlines():
                        parts = line.split(",")
                        if parts and parts[0].endswith(self.domain):
                            subdomains.add(parts[0].lower())
                    return subdomains
        except Exception:
            pass
        return set()

    async def alienvault(self) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            async with self.session.get(url, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = set()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").lower()
                        if hostname.endswith(self.domain):
                            subdomains.add(hostname)
                    return subdomains
        except Exception:
            pass
        return set()

    async def virustotal(self) -> Set[str]:
        if not self.config.virustotal_key:
            return set()
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=40"
        headers = {"x-apikey": self.config.virustotal_key}
        try:
            async with self.session.get(url, headers=headers, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {item["id"] for item in data.get("data", []) if item["id"].endswith(self.domain)}
        except Exception:
            pass
        return set()

    async def shodan(self) -> Set[str]:
        if not self.config.shodan_key:
            return set()
        url = f"https://api.shodan.io/dns/domain/{self.domain}?key={self.config.shodan_key}"
        try:
            async with self.session.get(url, timeout=self.config.timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subdomains = set()
                    for sub in data.get("subdomains", []):
                        subdomains.add(f"{sub}.{self.domain}".lower())
                    return subdomains
        except Exception:
            pass
        return set()

    async def run_all(self) -> Dict[str, Set[str]]:
        sources = {
            "CRT.sh": self.crt_sh(),
            "HackerTarget": self.hackertarget(),
            "AlienVault": self.alienvault(),
            "VirusTotal": self.virustotal(),
            "Shodan": self.shodan(),
        }

        results = {}
        for name, task in sources.items():
            try:
                results[name] = await task
            except Exception:
                results[name] = set()
        return results

    @staticmethod
    async def test_sources(config) -> List[Tuple[str, bool, str]]:
        test_domain = "example.com"
        headers = {"User-Agent": config.user_agent}
        async with aiohttp.ClientSession(headers=headers) as session:
            scraper = PassiveScraper(test_domain, config, session)
            tests = [
                ("CRT.sh", scraper.crt_sh()),
                ("HackerTarget", scraper.hackertarget()),
                ("AlienVault", scraper.alienvault()),
                ("VirusTotal", scraper.virustotal()),
                ("Shodan", scraper.shodan()),
            ]
            
            output = []
            for name, task in tests:
                try:
                    res = await task
                    key_attr = name.lower() + "_key"
                    if hasattr(config, key_attr) and not getattr(config, key_attr):
                        output.append((name, False, "Disabled (No API Key Provided)"))
                    else:
                        output.append((name, True, f"Online (Returned {len(res)} test items)"))
                except Exception as e:
                    output.append((name, False, f"Failed: {str(e)}"))
            return output
