"""
Tests for the logging module.
"""

import os
import json
import pytest
import tempfile
from pathlib import Path
import time
import threading
from src.logging.logger import Logger, LoggerError, LoggerInitializationError

class TestConfig:
    """Mock configuration class for testing."""
    def __init__(self, config_dict):
        self.config = config_dict
        
    def get(self, section, key, default=None):
        return self.config.get(section, {}).get(key, default)

@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for log files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir

@pytest.fixture
def logger_config(temp_log_dir):
    """Create a test configuration for the logger."""
    return TestConfig({
        'logging': {
            'level': 'debug',
            'format': 'json',
            'file': str(Path(temp_log_dir) / 'test.log'),
            'max_size_mb': 1,
            'backup_count': 3
        }
    })

def test_logger_initialization(logger_config, temp_log_dir):
    """Test logger initialization."""
    logger = Logger(logger_config)
    assert logger.initialized
    assert logger.running
    assert Path(logger_config.get('logging', 'file')).exists()

def test_logger_level_validation(logger_config):
    """Test log level validation."""
    logger = Logger(logger_config)
    
    # Test valid levels
    logger.log('debug', 'Debug message')
    logger.log('info', 'Info message')
    logger.log('warning', 'Warning message')
    logger.log('error', 'Error message')
    logger.log('critical', 'Critical message')
    
    # Test invalid level
    with pytest.raises(LoggerError):
        logger.log('invalid_level', 'Invalid message')

def test_logger_format_validation(logger_config, temp_log_dir):
    """Test log format validation."""
    logger = Logger(logger_config)
    
    # Log a test message
    test_data = {'key': 'value', 'number': 42}
    logger.log('info', 'Test message', **test_data)
    
    # Read the log file
    log_file = Path(logger_config.get('logging', 'file'))
    with open(log_file, 'r') as f:
        log_line = f.readlines()[-1]
        log_entry = json.loads(log_line)
        
        # Verify JSON structure
        assert 'timestamp' in log_entry
        assert 'level' in log_entry
        assert 'message' in log_entry
        assert log_entry['key'] == 'value'
        assert log_entry['number'] == 42

def test_logger_file_rotation(logger_config, temp_log_dir):
    """Test log file rotation."""
    logger = Logger(logger_config)
    log_file = Path(logger_config.get('logging', 'file'))
    
    # Write enough data to trigger rotation
    large_data = 'x' * 500000  # 500KB
    for _ in range(3):  # Write ~1.5MB to trigger rotation
        logger.log('info', large_data)
        time.sleep(0.1)  # Give time for rotation
    
    # Check that backup files exist
    assert log_file.exists()
    assert (log_file.parent / f"{log_file.name}.1").exists()

def test_logger_concurrent_writing(logger_config):
    """Test concurrent logging."""
    logger = Logger(logger_config)
    message_count = 100
    thread_count = 4
    
    def write_logs():
        for i in range(message_count):
            logger.log('info', f'Test message {i}')
    
    threads = [threading.Thread(target=write_logs) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    
    # Verify all messages were written
    with open(logger_config.get('logging', 'file'), 'r') as f:
        log_lines = f.readlines()
        assert len(log_lines) == message_count * thread_count

def test_logger_error_handling(temp_log_dir):
    """Test logger error handling."""
    # Test initialization with invalid path
    invalid_config = TestConfig({
        'logging': {
            'file': '/nonexistent/directory/test.log'
        }
    })
    with pytest.raises(LoggerInitializationError):
        Logger(invalid_config)
    
    # Test initialization with read-only directory
    read_only_dir = Path(temp_log_dir) / 'readonly'
    read_only_dir.mkdir()
    read_only_dir.chmod(0o444)  # Read-only
    
    readonly_config = TestConfig({
        'logging': {
            'file': str(read_only_dir / 'test.log')
        }
    })
    with pytest.raises(LoggerInitializationError):
        Logger(readonly_config)

def test_logger_cleanup(logger_config):
    """Test logger cleanup."""
    logger = Logger(logger_config)
    
    # Log some messages
    logger.log('info', 'Test message before cleanup')
    
    # Cleanup
    logger.cleanup()
    assert not logger.running
    
    # Verify no new logs can be written
    with pytest.raises(LoggerError):
        logger.log('info', 'Test message after cleanup') 