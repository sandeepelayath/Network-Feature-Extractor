# Network Feature Extractor

A high-performance network traffic feature extraction tool that uses eBPF for packet capture and generates feature sets compatible with network traffic analysis datasets.

## Features

- High-performance packet capture using eBPF
- Real-time extraction of network traffic features
- Support for both IPv4 and IPv6 traffic
- Multiple protocol support (TCP, UDP, ICMP, QUIC, SCTP, DCCP, RSVP)
- Configurable feature extraction modules
- CSV output with automatic rotation and compression
- Prometheus metrics for monitoring
- Comprehensive logging
- Modular architecture with enable/disable feature capability

## Requirements

- Linux kernel ≥ 5.2
- Python 3.8+
- BCC or libbpf development packages
- GCC and make

## Installation

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev gcc make linux-headers-$(uname -r) \
    libbpf-dev clang llvm libelf-dev

# Install the package
pip install -e .
```

## Usage

1. Edit the configuration file in `config/config.yaml`
2. Start the feature extractor:

```bash
./scripts/start.sh
```

3. Stop the feature extractor:

```bash
./scripts/stop.sh
```

## Configuration

See `config/config.yaml` for configuration options including:

- Network interface selection
- Feature enable/disable options
- Sampling configuration
- Output file settings

## Monitoring

Prometheus metrics are available at `http://localhost:5000/metrics`

## Output

CSV files are generated in the configured output directory with the following naming convention:
`netflow_YYYYMMDD_HHMMSS.csv`

Files are automatically rotated when they reach 250MB or after 30 minutes.
Rotated files are compressed using gzip.

## Documentation

See the `docs/` directory for detailed documentation.
