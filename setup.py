"""Setup script for SkillGuard."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README for the long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="skillguard-ai",
    version="0.1.0",
    description="AI Agent Skill Supply Chain Security Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="SkillGuard Contributors",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(include=["skillguard", "skillguard.*"]),
    package_data={
        "skillguard": [],
        "": ["rules/*.yaml"],
    },
    data_files=[
        ("rules", [
            "rules/execution.yaml",
            "rules/persistence.yaml",
            "rules/credentials.yaml",
            "rules/network.yaml",
            "rules/supply_chain.yaml",
            "rules/mcp_agent.yaml",
            "rules/obfuscation.yaml",
            "rules/destructive.yaml",
        ]),
    ],
    install_requires=[
        "click>=8.0",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    entry_points={
        "console_scripts": [
            "skillguard=skillguard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
