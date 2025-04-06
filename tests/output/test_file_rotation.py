"""
Tests for the file rotation component.
"""

import pytest
import os
import time
import gzip
from pathlib import Path
from src.output.file_rotation import FileRotator, FileRotationConfig

def test_file_rotator_initialization(test_config, mock_logger):
    """Test FileRotator initialization."""
    rotator = FileRotator(test_config, mock_logger)
    assert rotator is not None
    assert rotator.config == test_config
    assert rotator.logger == mock_logger
    assert not rotator.running

def test_file_rotation_config(test_config):
    """Test FileRotationConfig creation."""
    config = FileRotationConfig(
        size_limit_mb=test_config['output']['rotation']['size_limit_mb'],
        time_limit_min=test_config['output']['rotation']['time_limit_min'],
        compression_enabled=True,
        compression_algorithm='gzip',
        backup_count=5
    )
    assert config.size_limit_mb == 1
    assert config.time_limit_min == 1
    assert config.compression_enabled
    assert config.compression_algorithm == 'gzip'
    assert config.backup_count == 5

def test_file_rotation_by_size(test_config, mock_logger, test_data_dir):
    """Test file rotation based on size limit."""
    # Create test file
    test_file = test_data_dir / 'test.txt'
    rotator = FileRotator(test_config, mock_logger)
    rotator.set_current_file(str(test_file))
    
    # Write data exceeding size limit
    with open(test_file, 'w') as f:
        f.write('A' * (test_config['output']['rotation']['size_limit_mb'] * 1024 * 1024))
    
    rotator.update_file_size(os.path.getsize(test_file))
    rotator._rotate_file('size')
    
    # Verify rotation
    rotated_files = list(test_data_dir.glob('test_*.txt'))
    assert len(rotated_files) == 1
    assert rotated_files[0].exists()

def test_file_rotation_by_time(test_config, mock_logger, test_data_dir):
    """Test file rotation based on time limit."""
    # Create test file
    test_file = test_data_dir / 'test.txt'
    rotator = FileRotator(test_config, mock_logger)
    rotator.set_current_file(str(test_file))
    
    # Set file age beyond time limit
    rotator.current_file_start_time = time.time() - (test_config['output']['rotation']['time_limit_min'] * 60 + 1)
    
    # Create file
    with open(test_file, 'w') as f:
        f.write('Test content')
    
    rotator._rotate_file('time')
    
    # Verify rotation
    rotated_files = list(test_data_dir.glob('test_*.txt'))
    assert len(rotated_files) == 1
    assert rotated_files[0].exists()

def test_file_compression(test_config, mock_logger, test_data_dir):
    """Test file compression during rotation."""
    # Enable compression
    test_config['output']['compression']['enabled'] = True
    
    # Create test file
    test_file = test_data_dir / 'test.txt'
    rotator = FileRotator(test_config, mock_logger)
    rotator.set_current_file(str(test_file))
    
    # Write test data
    test_content = 'Test content for compression'
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    rotator._rotate_file('test')
    
    # Verify compression
    compressed_files = list(test_data_dir.glob('*.gz'))
    assert len(compressed_files) == 1
    
    # Verify content
    with gzip.open(compressed_files[0], 'rt') as f:
        assert f.read() == test_content

def test_backup_cleanup(test_config, mock_logger, test_data_dir):
    """Test cleanup of old backup files."""
    # Set small backup count
    test_config['output']['backup_count'] = 2
    
    # Create test file and multiple backups
    test_file = test_data_dir / 'test.txt'
    rotator = FileRotator(test_config, mock_logger)
    rotator.set_current_file(str(test_file))
    
    # Create multiple backups
    for i in range(4):
        backup_file = test_data_dir / f'test_{i}.txt'
        with open(backup_file, 'w') as f:
            f.write(f'Backup {i}')
    
    rotator._cleanup_old_files()
    
    # Verify only backup_count files remain
    backup_files = list(test_data_dir.glob('test_*.txt'))
    assert len(backup_files) <= test_config['output']['backup_count']

def test_error_handling(test_config, mock_logger):
    """Test error handling during rotation."""
    rotator = FileRotator(test_config, mock_logger)
    
    # Test rotation with non-existent file
    rotator.set_current_file('/nonexistent/path/test.txt')
    rotator._rotate_file('test')
    
    # Verify error was logged
    assert len(mock_logger.messages) > 0
    assert mock_logger.messages[-1][0] == 'error' 