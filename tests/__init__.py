"""
Test suite for the Network Feature Extractor.
Provides common test utilities and configurations.
"""

import os
import sys
import pytest
from pathlib import Path

# Add the project root directory to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Test configuration
@pytest.fixture
def test_config():
    """Provide a test configuration."""
    return {
        'network': {
            'interface': 'lo',
            'promiscuous': False,
            'buffer_size': 65536
        },
        'feature_extraction': {
            'enabled': True,
            'interval': 60
        },
        'output': {
            'format': 'csv',
            'path': '/tmp/test_output',
            'rotation': {
                'size_limit_mb': 1,
                'time_limit_min': 1
            }
        },
        'monitoring': {
            'enabled': True,
            'interval': 10
        },
        'logging': {
            'level': 'DEBUG',
            'format': 'json'
        }
    }

@pytest.fixture
def test_data_dir(tmp_path):
    """Provide a temporary directory for test data."""
    return tmp_path

@pytest.fixture
def mock_logger():
    """Provide a mock logger for testing."""
    class MockLogger:
        def __init__(self):
            self.messages = []
        
        def debug(self, msg, **kwargs):
            self.messages.append(('debug', msg, kwargs))
        
        def info(self, msg, **kwargs):
            self.messages.append(('info', msg, kwargs))
        
        def warning(self, msg, **kwargs):
            self.messages.append(('warning', msg, kwargs))
        
        def error(self, msg, **kwargs):
            self.messages.append(('error', msg, kwargs))
        
        def critical(self, msg, **kwargs):
            self.messages.append(('critical', msg, kwargs))
    
    return MockLogger() 