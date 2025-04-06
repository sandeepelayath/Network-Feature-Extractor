"""
Tests for the system statistics monitoring component.
"""

import pytest
import psutil
from src.monitoring.system_stats import SystemStats, SystemStatsCollector

def test_system_stats_initialization(test_config, mock_logger):
    """Test SystemStatsCollector initialization."""
    collector = SystemStatsCollector(test_config, mock_logger)
    assert collector is not None
    assert collector.config == test_config
    assert collector.logger == mock_logger
    assert not collector.running

def test_system_stats_start_stop(test_config, mock_logger):
    """Test starting and stopping the collector."""
    collector = SystemStatsCollector(test_config, mock_logger)
    
    # Test start
    assert collector.start()
    assert collector.running
    
    # Test stop
    collector.stop()
    assert not collector.running

def test_system_stats_collection(test_config, mock_logger):
    """Test statistics collection."""
    collector = SystemStatsCollector(test_config, mock_logger)
    collector.start()
    
    # Wait for collection interval
    import time
    time.sleep(test_config['monitoring']['interval'] + 1)
    
    stats = collector.get_current_stats()
    assert stats is not None
    assert isinstance(stats, SystemStats)
    
    # Verify basic stats are present
    assert stats.cpu_percent >= 0
    assert stats.memory_total > 0
    assert stats.disk_usage >= 0
    assert stats.network_bytes_sent >= 0
    assert stats.process_count >= 0
    
    collector.stop()

def test_system_stats_error_handling(test_config, mock_logger):
    """Test error handling during collection."""
    collector = SystemStatsCollector(test_config, mock_logger)
    
    # Test collection with invalid process
    stats = collector._collect_process_stats(-1)  # Invalid PID
    assert stats is None
    assert len(mock_logger.messages) > 0
    assert mock_logger.messages[-1][0] == 'error'

def test_system_stats_thread_safety(test_config, mock_logger):
    """Test thread safety of the collector."""
    collector = SystemStatsCollector(test_config, mock_logger)
    collector.start()
    
    # Access stats from multiple threads
    import threading
    results = []
    
    def get_stats():
        results.append(collector.get_current_stats())
    
    threads = [threading.Thread(target=get_stats) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    
    # Verify all threads got valid stats
    assert all(isinstance(r, SystemStats) for r in results)
    assert len(results) == 5
    
    collector.stop() 