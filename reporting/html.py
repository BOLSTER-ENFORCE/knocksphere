from jinja2 import Template
from typing import List, Dict, Any

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KnockSphere Report - {{ domain }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #090d16; color: #e2e8f0; margin: 0; padding: 2rem; }
        .container { max-width: 1250px; margin: 0 auto; }
        h1 { color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 0.75rem; margin-bottom: 1.5rem; }
        .stats { display: flex; gap: 1.25rem; margin-bottom: 2rem; }
        .card { background: #111827; padding: 1.25rem; border-radius: 10px; border: 1px solid #1f2937; flex: 1; }
        .card .num { font-size: 2.2rem; font-weight: bold; color: #38bdf8; margin-top: 0.5rem; }
        .card.warning .num { color: #f43f5e; }
        table { width: 100%; border-collapse: collapse; background: #111827; border-radius: 10px; overflow: hidden; border: 1px solid #1f2937; }
        th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid #1f2937; font-size: 0.95rem; }
        th { background: #1e293b; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        tr:hover { background: #1f2937; }
        .badge { padding: 0.25rem 0.55rem; border-radius: 6px; font-size: 0.75rem; font-weight: bold; display: inline-block; }
        .badge-success { background: #064e3b; color: #34d399; }
        .badge-warning { background: #881337; color: #fda4af; }
        .badge-info { background: #1e3a8a; color: #93c5fd; }
    </style>
</head>
<body>
    <div class="container">
        <h1>KnockSphere Security Report: {{ domain }}</h1>
        <div class="stats">
            <div class="card">
                <div>Total Subdomains Discovered</div>
                <div class="num">{{ results|length }}</div>
            </div>
            <div class="card warning">
                <div>Legacy TLS Warnings</div>
                <div class="num">{{ weak_tls_count }}</div>
            </div>
            <div class="card">
                <div>Live HTTP Services</div>
                <div class="num">{{ web_services_count }}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Addresses</th>
                    <th>Discovery Source</th>
                    <th>HTTP Status</th>
                    <th>Page Title</th>
                    <th>TLS Version</th>
                </tr>
            </thead>
            <tbody>
                {% for r in results %}
                <tr>
                    <td><strong>{{ r.subdomain }}</strong></td>
                    <td>{{ r.ips | join(', ') if r.ips else '-' }}</td>
                    <td><span class="badge badge-info">{{ r.source }}</span></td>
                    <td>
                        {% if r.http_status %}
                            <span class="badge badge-success">{{ r.http_status }}</span>
                        {% else %}
                            <span style="color:#64748b;">-</span>
                        {% endif %}
                    </td>
                    <td>{{ r.http_title or '-' }}</td>
                    <td>
                        {% if r.tls_weak %}
                            <span class="badge badge-warning">⚠️ {{ r.tls_version }}</span>
                        {% else %}
                            {{ r.tls_version or '-' }}
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

class HTMLReporter:
    @staticmethod
    def generate(domain: str, results: List[Dict[str, Any]], output_file: str):
        weak_tls = sum(1 for r in results if r.get("tls_weak"))
        web_services = sum(1 for r in results if r.get("http_status"))
        
        template = Template(HTML_TEMPLATE)
        rendered = template.render(
            domain=domain,
            results=results,
            weak_tls_count=weak_tls,
            web_services_count=web_services
        )
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
