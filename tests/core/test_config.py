"""
Tests for the configuration management component.
"""

import pytest
import yaml
from pathlib import Path
from src.core.config import Config, ConfigError

def test_config_initialization():
    """Test basic configuration initialization."""
    config = Config()
    assert config is not None
    assert isinstance(config, Config)

def test_config_validation():
    """Test configuration validation."""
    config = Config()
    
    # Test valid configuration
    valid_config = {
        'network': {
            'interface': 'eth0',
            'promiscuous': True,
            'mode': 'raw_socket'
        },
        'protocols': {
            'tcp': {'enabled': True},
            'udp': {'enabled': True}
        }
    }
    config.update_section('network', valid_config['network'])
    config.update_section('protocols', valid_config['protocols'])
    assert config.get('network', 'interface') == 'eth0'
    assert config.get('network', 'promiscuous') is True
    assert config.get('protocols', 'tcp')['enabled'] is True

def test_config_error_handling():
    """Test configuration error handling."""
    config = Config()
    
    # Test invalid configuration
    invalid_config = {
        'network': {
            'interface': 123,  # Invalid type
            'mode': 'invalid_mode'  # Invalid value
        }
    }
    with pytest.raises(ConfigError):
        config.update_section('network', invalid_config['network'])

def test_config_file_loading(tmp_path):
    """Test loading configuration from a file."""
    config = Config()
    
    # Create a temporary config file
    config_data = {
        'network': {
            'interface': 'eth0',
            'promiscuous': True
        }
    }
    config_file = tmp_path / "test_config.yaml"
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)
    
    # Load and verify
    config.load_config()
    assert config.get('network', 'interface') == 'eth0'
    assert config.get('network', 'promiscuous') is True

def test_config_default_values():
    """Test configuration default values."""
    config = Config()
    
    # Test getting non-existent key with default
    assert config.get('non', 'existent', 'default') == 'default'
    
    # Test getting non-existent key without default
    assert config.get('non', 'existent') is None

def test_config_nested_access():
    """Test accessing nested configuration values."""
    config = Config()
    
    test_config = {
        'network': {
            'interface': {
                'name': 'eth0',
                'settings': {
                    'mtu': 1500
                }
            }
        }
    }
    config.update_section('network', test_config['network'])
    
    assert config.get('network', 'interface')['name'] == 'eth0'
    assert config.get('network', 'interface')['settings']['mtu'] == 1500 