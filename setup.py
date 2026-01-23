"""
Setup configuration for HYDRA7 package.
This file provides backward compatibility with older build tools.
"""

from setuptools import setup, find_packages

# Read README for long description
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="hydra7",
    version="1.0.0",
    author="HYDRA Development Team",
    description="HYDRA7 - Secure mesh network with built-in DPI evasion and multi-hop routing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kirill-rdgaming/HYDRA-CORE",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
        "performance": [
            "uvloop>=0.17.0; sys_platform != 'win32'",
        ],
    },
    entry_points={
        "console_scripts": [
            "hydra7=hydra7.cli:main",
        ],
    },
)
