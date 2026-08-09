import uuid
import asyncio
import dns.asyncresolver
from typing import Set, List, Tuple

class WildcardDetector:
    def __init__(self, domain: str, resolvers: List[str], timeout: float = 3.0):
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = resolvers
        self.resolver.lifetime = timeout

    async def detect(self) -> Tuple[bool, Set[str]]:
        """Probes high-entropy random subdomains to verify wildcard DNS configuration."""
        test_subdomains = [f"ks-wildcard-{uuid.uuid4().hex[:10]}.{self.domain}" for _ in range(3)]
        resolved_ips: Set[str] = set()

        tasks = [self._resolve(sub) for sub in test_subdomains]
        results = await asyncio.gather(*tasks)

        match_count = 0
        for ips in results:
            if ips:
                match_count += 1
                resolved_ips.update(ips)

        is_wildcard = match_count >= 2
        return is_wildcard, resolved_ips

    async def _resolve(self, fqdn: str) -> List[str]:
        try:
            answers = await self.resolver.resolve(fqdn, "A")
            return [rdata.to_text() for rdata in answers]
        except Exception:
            return []
