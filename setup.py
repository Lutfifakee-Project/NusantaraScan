from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="nusantarascan",
    version="0.2.0",
    description="Advanced Binary Analysis Tool",
    keywords="malware analysis reverse engineering security",
    project_urls={"Source": "https://github.com/Lutfifakee-Project/NusantaraScan",},
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Lutfifakee",
    author_email="lutfifakeeproject@proton.me",
    url="https://github.com/Lutfifakee-Project/NusantaraScan",
    license="GPL-3.0-or-later",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "pefile>=2023.2.7",
        "pyelftools>=0.29",
        "capstone>=5.0.1",
        "yara-python>=4.5.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "python-magic>=0.4.27",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "nusantarascan=nusantarascan.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
