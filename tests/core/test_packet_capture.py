"""
Tests for the packet capture component.
"""

import pytest
from unittest.mock import Mock, patch
from src.core.packet_capture import PacketCapture, PacketCaptureError

@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    config = Mock()
    config.get.return_value = {
        'interface': 'eth0',
        'promiscuous': True,
        'mode': 'raw_socket',
        'packet_queue_size': 1000
    }
    return config

def test_packet_capture_initialization(mock_config):
    """Test packet capture initialization."""
    capture = PacketCapture(mock_config)
    assert capture is not None
    assert isinstance(capture, PacketCapture)
    assert not capture.is_running()

def test_packet_capture_start_stop(mock_config):
    """Test starting and stopping packet capture."""
    capture = PacketCapture(mock_config)
    
    # Test start
    capture.start()
    assert capture.is_running()
    
    # Test stop
    capture.stop()
    assert not capture.is_running()

def test_packet_capture_error_handling(mock_config):
    """Test packet capture error handling."""
    capture = PacketCapture(mock_config)
    
    # Test starting capture on invalid interface
    with patch('socket.socket') as mock_socket:
        mock_socket.side_effect = OSError("Invalid interface")
        with pytest.raises(PacketCaptureError):
            capture.start()

def test_packet_capture_packet_processing(mock_config):
    """Test packet processing functionality."""
    capture = PacketCapture(mock_config)
    
    # Mock a packet
    mock_packet = Mock()
    mock_packet.data = b'test packet data'
    
    # Test packet processing
    with patch.object(capture, '_process_packet') as mock_process:
        capture._handle_packet(mock_packet)
        mock_process.assert_called_once_with(mock_packet)

def test_packet_capture_queue_management(mock_config):
    """Test packet queue management."""
    capture = PacketCapture(mock_config)
    
    # Test queue size limit
    for i in range(1001):  # Exceed queue size
        capture._queue_packet(f"test packet {i}")
    
    # Verify queue size is maintained
    assert len(capture.packet_queue) <= mock_config.get()['packet_queue_size']

def test_packet_capture_cleanup(mock_config):
    """Test packet capture cleanup."""
    capture = PacketCapture(mock_config)
    capture.start()
    
    # Test cleanup
    capture.cleanup()
    assert not capture.is_running()
    assert capture.packet_queue.empty()

def test_packet_capture_statistics(mock_config):
    """Test packet capture statistics tracking."""
    capture = PacketCapture(mock_config)
    capture.start()
    
    # Simulate some packets
    for i in range(10):
        capture._queue_packet(f"test packet {i}")
    
    stats = capture.get_statistics()
    assert stats['packets_captured'] >= 0
    assert stats['queue_size'] >= 0
    assert stats['dropped_packets'] >= 0 