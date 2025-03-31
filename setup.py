from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setup(
    name="network-feature-extractor",
    version="0.1.0",
    author="Network Feature Extractor Team",
    description="A high-performance network traffic feature extraction tool using eBPF",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "net-feature-extract=src.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["ebpf/*.c", "config/*.yaml"],
    },
)
