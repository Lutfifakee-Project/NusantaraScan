from setuptools import setup, find_packages

setup(
    name="nusantarascan",
    version="0.1.0",
    description="NusantaraScan - Advanced Binary Analysis Tool dengan semangat Nusantara",
    author="Lutfifakee",
    author_email="lutfifakeeproject@proton.me",
    url="https://github.com/Lutfifakee-Project/NusantaraScan",
    packages=find_packages(),
    install_requires=[
        "pefile>=2023.2.7",
        "pyelftools>=0.29",
        "capstone>=5.0.1",
        "yara-python>=4.5.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "python-magic>=0.4.27",
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