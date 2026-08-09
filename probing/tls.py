import ssl
import asyncio
from datetime import datetime
from typing import Dict, Any

class TLSInspector:
    @staticmethod
    async def inspect(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
        res = {
            "tls_version": None,
            "tls_issuer": None,
            "tls_expiry": None,
            "tls_weak": False,
            "error": None
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            conn = asyncio.open_connection(host, port, ssl=ctx)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                res["tls_version"] = ssl_obj.version()
                
                # Highlight outdated protocols
                if res["tls_version"] in ["TLSv1", "TLSv1.1"]:
                    res["tls_weak"] = True

                cert = ssl_obj.getpeercert(binary_form=False) or {}
                
                issuer = cert.get("issuer", ())
                issuer_str = []
                for item in issuer:
                    for k, v in item:
                        if k == "organizationName":
                            issuer_str.append(v)
                res["tls_issuer"] = ", ".join(issuer_str) if issuer_str else "Unknown"

                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        res["tls_expiry"] = exp_dt.strftime("%Y-%m-%d")
                    except Exception:
                        res["tls_expiry"] = not_after

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            res["error"] = str(e)

        return res
