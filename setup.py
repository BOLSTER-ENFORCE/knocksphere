from setuptools import setup, find_packages

setup(
    name="knocksphere",
    version="1.0.0",
    description="Async Subdomain Discovery & Threat Intelligence Framework",
    author="Security Analyst",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "dnspython>=2.5.0",
        "rich>=13.7.0",
        "PyYAML>=6.0.1",
        "jinja2>=3.1.2",
    ],
    entry_points={
        "console_scripts": [
            "knocksphere=knocksphere.cli:main",
        ],
    },
    python_requires=">=3.9",
)
