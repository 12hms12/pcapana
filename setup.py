from setuptools import setup, find_packages

setup(
    name="pcapana",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pyshark",
    ],
    entry_points={
        "console_scripts": [
            "pcapana = pcapanalyzer.cli:main",
        ],
    },
    author="Harsh M Shah",
    description="Analyze PCAP files for protocol stats, bandwidth usage, and visited domains.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/12hms12/pcapana", 
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.7",
)
