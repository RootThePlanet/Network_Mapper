"""Setup configuration for nmap++."""

from setuptools import find_packages, setup

setup(
    name="nmap-plusplus",
    version="1.0.0",
    description="Discover and visualise your network topology",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    install_requires=[
        "flask>=2.3.0",
        "flask-cors>=4.0.0",
        "networkx>=3.1",
        "PyYAML>=6.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov"],
        "full": ["netifaces2>=0.0.1"],
        "mdns": ["zeroconf>=0.115.0"],
    },
    entry_points={
        "console_scripts": [
            "nmap-plusplus=main:main",
        ]
    },
)
