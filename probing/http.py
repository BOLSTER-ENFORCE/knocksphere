import asyncio
import aiohttp
import re
from typing import Dict, Any
from knocksphere.probing.tls import TLSInspector

class HTTPProber:
    def __init__(self, session: aiohttp.ClientSession, timeout: float = 5.0):
        self.session = session
        self.timeout = timeout
        self.title_regex = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    async def probe(self, subdomain: str) -> Dict[str, Any]:
        result = {
            "http_status": None,
            "http_title": None,
            "http_url": None,
            "tls_version": None,
            "tls_issuer": None,
            "tls_expiry": None,
            "tls_weak": False
        }

        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                async with self.session.get(url, timeout=self.timeout, allow_redirects=True, ssl=False) as resp:
                    result["http_status"] = resp.status
                    result["http_url"] = str(resp.url)
                    
                    text = await resp.text(errors="ignore")
                    match = self.title_regex.search(text)
                    if match:
                        result["http_title"] = match.group(1).strip().replace("\n", " ")[:100]
                    else:
                        result["http_title"] = "[No Title]"

                    if scheme == "https":
                        tls_info = await TLSInspector.inspect(subdomain, timeout=self.timeout)
                        result.update({
                            "tls_version": tls_info["tls_version"],
                            "tls_issuer": tls_info["tls_issuer"],
                            "tls_expiry": tls_info["tls_expiry"],
                            "tls_weak": tls_info["tls_weak"]
                        })

                    break
            except Exception:
                continue

        return result
