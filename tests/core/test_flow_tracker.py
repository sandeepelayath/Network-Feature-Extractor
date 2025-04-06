"""
Tests for the flow tracker component.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from src.core.flow_tracker import FlowTracker, FlowTrackerError

@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    config = Mock()
    config.get.return_value = {
        'cleanup_interval': 60,
        'cleanup_threshold': 1000,
        'enable_dynamic_cleanup': True,
        'max_flows': 10000
    }
    return config

def test_flow_tracker_initialization(mock_config):
    """Test flow tracker initialization."""
    tracker = FlowTracker(mock_config)
    assert tracker is not None
    assert isinstance(tracker, FlowTracker)
    assert not tracker.is_running()

def test_flow_tracker_start_stop(mock_config):
    """Test starting and stopping flow tracker."""
    tracker = FlowTracker(mock_config)
    
    # Test start
    tracker.start()
    assert tracker.is_running()
    
    # Test stop
    tracker.stop()
    assert not tracker.is_running()

def test_flow_tracker_flow_creation(mock_config):
    """Test flow creation and tracking."""
    tracker = FlowTracker(mock_config)
    tracker.start()
    
    # Create a test flow
    flow_key = ('192.168.1.1', '192.168.1.2', 12345, 80, 6)  # (src_ip, dst_ip, src_port, dst_port, protocol)
    flow_data = {
        'start_time': datetime.now(),
        'packet_count': 1,
        'byte_count': 100
    }
    
    tracker.update_flow(flow_key, flow_data)
    assert flow_key in tracker.active_flows

def test_flow_tracker_flow_timeout(mock_config):
    """Test flow timeout handling."""
    tracker = FlowTracker(mock_config)
    tracker.start()
    
    # Create an old flow
    old_time = datetime.now() - timedelta(minutes=5)
    flow_key = ('192.168.1.1', '192.168.1.2', 12345, 80, 6)
    flow_data = {
        'start_time': old_time,
        'last_seen': old_time,
        'packet_count': 1,
        'byte_count': 100
    }
    
    tracker.update_flow(flow_key, flow_data)
    tracker._cleanup_flows()
    assert flow_key not in tracker.active_flows

def test_flow_tracker_statistics(mock_config):
    """Test flow tracker statistics."""
    tracker = FlowTracker(mock_config)
    tracker.start()
    
    # Add some flows
    for i in range(5):
        flow_key = (f'192.168.1.{i}', '192.168.1.100', 12345 + i, 80, 6)
        flow_data = {
            'start_time': datetime.now(),
            'packet_count': i + 1,
            'byte_count': (i + 1) * 100
        }
        tracker.update_flow(flow_key, flow_data)
    
    stats = tracker.get_statistics()
    assert stats['active_flows'] == 5
    assert stats['total_packets'] >= 5
    assert stats['total_bytes'] >= 500

def test_flow_tracker_cleanup(mock_config):
    """Test flow tracker cleanup."""
    tracker = FlowTracker(mock_config)
    tracker.start()
    
    # Add some flows
    for i in range(10):
        flow_key = (f'192.168.1.{i}', '192.168.1.100', 12345 + i, 80, 6)
        flow_data = {
            'start_time': datetime.now(),
            'packet_count': 1,
            'byte_count': 100
        }
        tracker.update_flow(flow_key, flow_data)
    
    # Test cleanup
    tracker.cleanup()
    assert not tracker.is_running()
    assert len(tracker.active_flows) == 0

def test_flow_tracker_error_handling(mock_config):
    """Test flow tracker error handling."""
    tracker = FlowTracker(mock_config)
    
    # Test invalid flow key
    with pytest.raises(FlowTrackerError):
        tracker.update_flow(('invalid',), {})

def test_flow_tracker_dynamic_cleanup(mock_config):
    """Test dynamic cleanup functionality."""
    tracker = FlowTracker(mock_config)
    tracker.start()
    
    # Add flows up to threshold
    for i in range(1001):  # Exceed cleanup threshold
        flow_key = (f'192.168.1.{i}', '192.168.1.100', 12345 + i, 80, 6)
        flow_data = {
            'start_time': datetime.now(),
            'packet_count': 1,
            'byte_count': 100
        }
        tracker.update_flow(flow_key, flow_data)
    
    # Verify cleanup was triggered
    assert len(tracker.active_flows) < 1001 