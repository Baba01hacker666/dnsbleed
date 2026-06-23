from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dnsbleed",
    version="1.0.0",
    author="dnsbleed",
    description="DNS Response Timing & Privacy Analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/baba01hacker/dnsbleed",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        "console_scripts": [
            "dnsbleed=dnsbleed.cli:main",
        ],
    },
)
