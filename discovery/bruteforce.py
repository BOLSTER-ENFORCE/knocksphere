import asyncio
import dns.asyncresolver
from typing import List, Set, Dict, Any, Callable, Optional

class AsyncBruteforcer:
    def __init__(
        self,
        domain: str,
        wordlist: List[str],
        resolvers: List[str],
        concurrency: int = 100,
        timeout: float = 3.0,
        wildcard_ips: Optional[Set[str]] = None
    ):
        self.domain = domain
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.wildcard_ips = wildcard_ips or set()
        self.semaphore = asyncio.Semaphore(concurrency)
        
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = resolvers
        self.resolver.lifetime = timeout

    async def _resolve_host(self, sub: str) -> Optional[Dict[str, Any]]:
        fqdn = f"{sub}.{self.domain}" if not sub.endswith(f".{self.domain}") else sub
        async with self.semaphore:
            try:
                answers = await self.resolver.resolve(fqdn, "A")
                ips = [rdata.to_text() for rdata in answers]
                
                if self.wildcard_ips and set(ips).issubset(self.wildcard_ips):
                    return None
                    
                return {"subdomain": fqdn, "ips": ips, "source": "bruteforce"}
            except Exception:
                return None

    async def run(self, progress_callback: Optional[Callable[[], None]] = None) -> List[Dict[str, Any]]:
        tasks = []
        for word in self.wordlist:
            word = word.strip()
            if word:
                task = asyncio.create_task(self._resolve_host(word))
                if progress_callback:
                    task.add_done_callback(lambda _: progress_callback())
                tasks.append(task)

        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
