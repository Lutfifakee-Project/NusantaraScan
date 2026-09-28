import re
from pathlib import Path
from setuptools import setup, find_packages


# Baca versi dari binscan/__init__.py (single source of truth)
init_file = Path(__file__).parent / "binscan" / "__init__.py"
version = re.search(
    r'__version__\s*=\s*"([^"]+)"',
    init_file.read_text(encoding="utf-8"),
).group(1)

# Baca README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8")


setup(
    name="binscan",
    version=version,
    description="NusantaraScan - Advanced Binary Analysis Tool for modern security workflows",
    keywords="malware analysis reverse engineering security binary scanner",
    project_urls={
        "Homepage": "https://github.com/Lutfifakee-Project/NusantaraScan",
        "Source": "https://github.com/Lutfifakee-Project/NusantaraScan",
        "Bug Reports": "https://github.com/Lutfifakee-Project/NusantaraScan/issues",
    },
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Lutfifakee",
    author_email="lutfifakeeproject@proton.me",
    url="https://github.com/Lutfifakee-Project/NusantaraScan",
    license="GPL-3.0-or-later",
    packages=find_packages(exclude=["tests*", "docs*"]),
    include_package_data=True,
    package_data={
        "binscan": ["signatures/yara_rules/**/*.yar", "signatures/yara_rules/**/*.yara"],
    },
    install_requires=[
        "pefile>=2023.2.7",
        "pyelftools>=0.29",
        "capstone>=5.0.1",
        "yara-python>=4.5.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        'python-magic>=0.4.27; sys_platform != "win32"',
        'python-magic-bin>=0.4.14; sys_platform == "win32"',
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "binscan=binscan.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)