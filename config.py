import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Config:
    concurrency: int = 100
    timeout: float = 5.0
    user_agent: str = "KnockSphere/1.0 (Security Intelligence Agent)"
    dns_servers: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    virustotal_key: Optional[str] = None
    shodan_key: Optional[str] = None
    securitytrails_key: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        config = cls()
        if not path or not os.path.exists(path):
            if os.path.exists("config.yaml"):
                path = "config.yaml"
            elif os.path.exists("config.example.yaml"):
                path = "config.example.yaml"
            else:
                return config

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            gen = data.get("general", {})
            config.concurrency = gen.get("concurrency", config.concurrency)
            config.timeout = float(gen.get("timeout", config.timeout))
            config.user_agent = gen.get("user_agent", config.user_agent)
            config.dns_servers = gen.get("dns_servers", config.dns_servers)

            keys = data.get("api_keys", {})
            config.virustotal_key = keys.get("virustotal") or os.getenv("VIRUSTOTAL_API_KEY")
            config.shodan_key = keys.get("shodan") or os.getenv("SHODAN_API_KEY")
            config.securitytrails_key = keys.get("securitytrails") or os.getenv("SECURITYTRAILS_API_KEY")
        except Exception as e:
            print(f"[!] Warning: Failed to parse configuration file ({e}). Using standard defaults.")

        return config
