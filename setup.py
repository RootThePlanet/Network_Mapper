"""Setup configuration for Network Mapper."""

from setuptools import find_packages, setup

setup(
    name="network-mapper",
    version="1.0.0",
    description="Discover and visualise your network topology",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    install_requires=[
        "flask>=2.3.0",
        "flask-cors>=4.0.0",
        "networkx>=3.1",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov"],
        "full": ["netifaces2>=0.0.1"],
    },
    entry_points={
        "console_scripts": [
            "network-mapper=main:main",
        ]
    },
)
