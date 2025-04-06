"""
Test fixtures for Network Feature Extractor.
"""

import os
import pytest
import tempfile
from pathlib import Path
import yaml

@pytest.fixture(scope="session")
def test_data_dir():
    """Create a temporary directory for test data."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)

@pytest.fixture(scope="session")
def test_config():
    """Create a test configuration."""
    config = {
        'network': {
            'interface': 'lo',  # Use loopback interface for testing
            'promiscuous': True,
            'mode': 'raw_socket',  # Use raw socket instead of XDP for testing
            'sampling': {'enabled': False, 'rate': 1.0},
            'packet_queue_size': 1000,
            'ring_buffer_size': 65536,
            'overflow_policy': 'drop'
        },
        'protocols': {
            'tcp': {'enabled': True, 'timeout': 300},
            'udp': {'enabled': True, 'timeout': 180},
            'icmp': {'enabled': True, 'timeout': 60},
            'ipv4': {'enabled': True},
            'ipv6': {'enabled': True}
        },
        'flow_tracker': {
            'cleanup_interval': 10,
            'cleanup_threshold': 1000,
            'enable_dynamic_cleanup': True,
            'max_flows': 10000
        },
        'output': {
            'directory': None,  # Will be set by fixture
            'filename_prefix': 'test_netflow',
            'rotation': {
                'size_limit_mb': 10,
                'time_limit_min': 5
            },
            'compression': {
                'enabled': True,
                'algorithm': 'gzip'
            }
        },
        'logging': {
            'level': 'DEBUG',
            'format': 'JSON',
            'file': None,  # Will be set by fixture
            'max_size_mb': 10,
            'backup_count': 3
        },
        'monitoring': {
            'system_stats': {
                'enabled': True,
                'interval': 5
            },
            'prometheus': {
                'enabled': True,
                'port': 9090
            }
        }
    }
    return config

@pytest.fixture(scope="function")
def config_with_paths(test_config, test_data_dir):
    """Create a configuration with actual paths."""
    config = test_config.copy()
    config['output']['directory'] = str(test_data_dir / 'output')
    config['logging']['file'] = str(test_data_dir / 'logs' / 'test.log')
    
    # Create necessary directories
    os.makedirs(config['output']['directory'], exist_ok=True)
    os.makedirs(os.path.dirname(config['logging']['file']), exist_ok=True)
    
    return config

@pytest.fixture(scope="function")
def sample_flow_data():
    """Create sample flow data for testing."""
    return {
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.200',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 6,  # TCP
        'start_time': 1648732800.0,
        'end_time': 1648732860.0,
        'packets': [
            {
                'timestamp': 1648732800.0,
                'length': 64,
                'flags': 0x02,  # SYN
                'direction': 'forward'
            },
            {
                'timestamp': 1648732800.1,
                'length': 64,
                'flags': 0x12,  # SYN-ACK
                'direction': 'backward'
            },
            {
                'timestamp': 1648732800.2,
                'length': 52,
                'flags': 0x10,  # ACK
                'direction': 'forward'
            }
        ]
    }

@pytest.fixture(scope="function")
def sample_packet_data():
    """Create sample packet data for testing."""
    return {
        'timestamp': 1648732800.0,
        'length': 64,
        'protocol': 6,  # TCP
        'src_ip': '192.168.1.100',
        'dst_ip': '192.168.1.200',
        'src_port': 12345,
        'dst_port': 80,
        'flags': 0x02,  # SYN
        'payload': b'Test packet payload'
    } 