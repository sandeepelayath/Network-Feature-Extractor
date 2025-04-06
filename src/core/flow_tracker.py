"""
Flow Tracker module for the Network Feature Extractor.
Tracks flow state and calculates flow-level metrics.
"""

import time
import logging
import threading
from typing import Dict, List, Any, Callable, Optional
from collections import defaultdict
from datetime import datetime
import copy
from dataclasses import dataclass, field
import structlog
from ..logging.logger import Logger

from structlog import get_logger
import ipaddress
import math
import statistics

# Import local modules
from .config import Config
from ..feature_extraction import BaseFeatureExtractor, FeatureExtractorRegistry
from ..feature_extraction.basic_metrics import BasicMetricsExtractor
from ..feature_extraction.packet_length import PacketLengthExtractor
from ..feature_extraction.flag_analysis import FlagAnalysisExtractor
from ..feature_extraction.timing_metrics import TimingMetricsExtractor

# Custom exception classes
class FlowTrackerError(Exception):
    """Base exception for flow tracker errors."""
    pass

class FlowTrackerInitializationError(FlowTrackerError):
    """Raised when flow tracker initialization fails."""
    pass

class FlowTrackerCleanupError(FlowTrackerError):
    """Raised when flow tracker cleanup fails."""
    pass

class FlowTrackerStateError(FlowTrackerError):
    """Raised when flow tracker is in an invalid state."""
    pass

class FlowTrackerValidationError(FlowTrackerError):
    """Raised when flow validation fails."""
    pass

class FlowTrackerIOError(FlowTrackerError):
    """Raised when I/O operations fail."""
    pass

class FlowTrackerStatsError(FlowTrackerError):
    """Raised when statistics operations fail."""
    pass

class FlowTrackerTimeoutError(FlowTrackerError):
    """Raised when flow operations timeout."""
    pass

class FlowTrackerResourceError(FlowTrackerError):
    """Raised when resource limits are exceeded."""
    pass

class FlowError(Exception):
    """Base exception for flow-related errors."""
    pass

class FlowKeyError(FlowError):
    """Exception raised for invalid flow keys."""
    pass

class FlowUpdateError(FlowError):
    """Exception raised for flow update errors."""
    pass


@dataclass(frozen=True)
class FlowKey:
    """Key for identifying unique flows."""
    
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    
    def __post_init__(self):
        """
        Validate flow key fields.
        
        Raises:
            FlowKeyError: If flow key is invalid
        """
        try:
            # Validate IP addresses
            if not isinstance(self.src_ip, str) or not isinstance(self.dst_ip, str):
                raise FlowKeyError("IP addresses must be strings")
            
            # Validate IP address format
            try:
                src_ip_obj = ipaddress.ip_address(self.src_ip)
                dst_ip_obj = ipaddress.ip_address(self.dst_ip)
            except ValueError:
                raise FlowKeyError("Invalid IP address format")
            
            # Validate ports
            if not isinstance(self.src_port, int) or not isinstance(self.dst_port, int):
                raise FlowKeyError("Ports must be integers")
            
            if not (0 <= self.src_port <= 65535):
                raise FlowKeyError("Source port must be between 0 and 65535")
            
            if not (0 <= self.dst_port <= 65535):
                raise FlowKeyError("Destination port must be between 0 and 65535")
            
            # Validate protocol
            if not isinstance(self.protocol, int):
                raise FlowKeyError("Protocol must be an integer")
            
            if not (0 <= self.protocol <= 255):
                raise FlowKeyError("Protocol must be between 0 and 255")
            
        except Exception as e:
            raise FlowKeyError(f"Invalid flow key: {str(e)}")
    
    def __hash__(self) -> int:
        """
        Compute hash of flow key.
        
        Returns:
            Hash value
            
        Raises:
            FlowKeyError: If hash computation fails
        """
        try:
            return hash((
                self.src_ip,
                self.dst_ip,
                self.src_port,
                self.dst_port,
                self.protocol
            ))
        except Exception as e:
            raise FlowKeyError(f"Failed to compute flow key hash: {str(e)}")
    
    def __eq__(self, other: object) -> bool:
        """
        Compare flow keys for equality.
        
        Args:
            other: Other flow key
            
        Returns:
            True if flow keys are equal, False otherwise
            
        Raises:
            FlowKeyError: If comparison fails
        """
        try:
            if not isinstance(other, FlowKey):
                return False
            
            return (
                self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol
            )
        except Exception as e:
            raise FlowKeyError(f"Failed to compare flow keys: {str(e)}")


@dataclass
class FlowStats:
    """Statistics for a network flow."""
    
    # Basic flow information
    flow_key: FlowKey
    start_time: float
    end_time: float
    duration: float
    
    # Packet counts and sizes
    total_packets: int
    total_bytes: int
    fwd_packets: int
    fwd_bytes: int
    bwd_packets: int
    bwd_bytes: int
    
    # Packet length statistics
    fwd_pkt_len_max: int
    fwd_pkt_len_min: int
    fwd_pkt_len_mean: float
    fwd_pkt_len_std: float
    bwd_pkt_len_max: int
    bwd_pkt_len_min: int
    bwd_pkt_len_mean: float
    bwd_pkt_len_std: float
    
    # Inter-arrival time statistics
    fwd_iat_max: float
    fwd_iat_min: float
    fwd_iat_mean: float
    fwd_iat_std: float
    bwd_iat_max: float
    bwd_iat_min: float
    bwd_iat_mean: float
    bwd_iat_std: float
    
    # Flow IAT statistics
    flow_iat_max: float
    flow_iat_min: float
    flow_iat_mean: float
    flow_iat_std: float
    
    # Flag counts
    fin_count: int
    syn_count: int
    rst_count: int
    psh_count: int
    ack_count: int
    urg_count: int
    cwe_count: int
    ece_count: int
    
    # Window sizes
    init_win_bytes_fwd: int
    init_win_bytes_bwd: int
    
    # Activity statistics
    active_count: int
    idle_count: int
    active_time: float
    idle_time: float
    
    def __post_init__(self):
        """
        Validate flow statistics.
        
        Raises:
            FlowStatsError: If flow statistics are invalid
        """
        try:
            # Validate basic flow information
            if not isinstance(self.flow_key, FlowKey):
                raise FlowStatsError("Invalid flow key")
            
            if not isinstance(self.start_time, (int, float)) or self.start_time <= 0:
                raise FlowStatsError("Invalid start time")
            
            if not isinstance(self.end_time, (int, float)) or self.end_time <= 0:
                raise FlowStatsError("Invalid end time")
            
            if not isinstance(self.duration, (int, float)) or self.duration < 0:
                raise FlowStatsError("Invalid duration")
            
            # Validate packet counts and sizes
            if not isinstance(self.total_packets, int) or self.total_packets < 0:
                raise FlowStatsError("Invalid total packets")
            
            if not isinstance(self.total_bytes, int) or self.total_bytes < 0:
                raise FlowStatsError("Invalid total bytes")
            
            if not isinstance(self.fwd_packets, int) or self.fwd_packets < 0:
                raise FlowStatsError("Invalid forward packets")
            
            if not isinstance(self.fwd_bytes, int) or self.fwd_bytes < 0:
                raise FlowStatsError("Invalid forward bytes")
            
            if not isinstance(self.bwd_packets, int) or self.bwd_packets < 0:
                raise FlowStatsError("Invalid backward packets")
            
            if not isinstance(self.bwd_bytes, int) or self.bwd_bytes < 0:
                raise FlowStatsError("Invalid backward bytes")
            
            # Validate packet length statistics
            if not isinstance(self.fwd_pkt_len_max, int) or self.fwd_pkt_len_max < 0:
                raise FlowStatsError("Invalid forward packet length maximum")
            
            if not isinstance(self.fwd_pkt_len_min, int) or self.fwd_pkt_len_min < 0:
                raise FlowStatsError("Invalid forward packet length minimum")
            
            if not isinstance(self.fwd_pkt_len_mean, (int, float)) or self.fwd_pkt_len_mean < 0:
                raise FlowStatsError("Invalid forward packet length mean")
            
            if not isinstance(self.fwd_pkt_len_std, (int, float)) or self.fwd_pkt_len_std < 0:
                raise FlowStatsError("Invalid forward packet length standard deviation")
            
            if not isinstance(self.bwd_pkt_len_max, int) or self.bwd_pkt_len_max < 0:
                raise FlowStatsError("Invalid backward packet length maximum")
            
            if not isinstance(self.bwd_pkt_len_min, int) or self.bwd_pkt_len_min < 0:
                raise FlowStatsError("Invalid backward packet length minimum")
            
            if not isinstance(self.bwd_pkt_len_mean, (int, float)) or self.bwd_pkt_len_mean < 0:
                raise FlowStatsError("Invalid backward packet length mean")
            
            if not isinstance(self.bwd_pkt_len_std, (int, float)) or self.bwd_pkt_len_std < 0:
                raise FlowStatsError("Invalid backward packet length standard deviation")
            
            # Validate inter-arrival time statistics
            if not isinstance(self.fwd_iat_max, (int, float)) or self.fwd_iat_max < 0:
                raise FlowStatsError("Invalid forward inter-arrival time maximum")
            
            if not isinstance(self.fwd_iat_min, (int, float)) or self.fwd_iat_min < 0:
                raise FlowStatsError("Invalid forward inter-arrival time minimum")
            
            if not isinstance(self.fwd_iat_mean, (int, float)) or self.fwd_iat_mean < 0:
                raise FlowStatsError("Invalid forward inter-arrival time mean")
            
            if not isinstance(self.fwd_iat_std, (int, float)) or self.fwd_iat_std < 0:
                raise FlowStatsError("Invalid forward inter-arrival time standard deviation")
            
            if not isinstance(self.bwd_iat_max, (int, float)) or self.bwd_iat_max < 0:
                raise FlowStatsError("Invalid backward inter-arrival time maximum")
            
            if not isinstance(self.bwd_iat_min, (int, float)) or self.bwd_iat_min < 0:
                raise FlowStatsError("Invalid backward inter-arrival time minimum")
            
            if not isinstance(self.bwd_iat_mean, (int, float)) or self.bwd_iat_mean < 0:
                raise FlowStatsError("Invalid backward inter-arrival time mean")
            
            if not isinstance(self.bwd_iat_std, (int, float)) or self.bwd_iat_std < 0:
                raise FlowStatsError("Invalid backward inter-arrival time standard deviation")
            
            # Validate flow IAT statistics
            if not isinstance(self.flow_iat_max, (int, float)) or self.flow_iat_max < 0:
                raise FlowStatsError("Invalid flow inter-arrival time maximum")
            
            if not isinstance(self.flow_iat_min, (int, float)) or self.flow_iat_min < 0:
                raise FlowStatsError("Invalid flow inter-arrival time minimum")
            
            if not isinstance(self.flow_iat_mean, (int, float)) or self.flow_iat_mean < 0:
                raise FlowStatsError("Invalid flow inter-arrival time mean")
            
            if not isinstance(self.flow_iat_std, (int, float)) or self.flow_iat_std < 0:
                raise FlowStatsError("Invalid flow inter-arrival time standard deviation")
            
            # Validate flag counts
            if not isinstance(self.fin_count, int) or self.fin_count < 0:
                raise FlowStatsError("Invalid FIN count")
            
            if not isinstance(self.syn_count, int) or self.syn_count < 0:
                raise FlowStatsError("Invalid SYN count")
            
            if not isinstance(self.rst_count, int) or self.rst_count < 0:
                raise FlowStatsError("Invalid RST count")
            
            if not isinstance(self.psh_count, int) or self.psh_count < 0:
                raise FlowStatsError("Invalid PSH count")
            
            if not isinstance(self.ack_count, int) or self.ack_count < 0:
                raise FlowStatsError("Invalid ACK count")
            
            if not isinstance(self.urg_count, int) or self.urg_count < 0:
                raise FlowStatsError("Invalid URG count")
            
            if not isinstance(self.cwe_count, int) or self.cwe_count < 0:
                raise FlowStatsError("Invalid CWE count")
            
            if not isinstance(self.ece_count, int) or self.ece_count < 0:
                raise FlowStatsError("Invalid ECE count")
            
            # Validate window sizes
            if not isinstance(self.init_win_bytes_fwd, int) or self.init_win_bytes_fwd < 0:
                raise FlowStatsError("Invalid forward initial window size")
            
            if not isinstance(self.init_win_bytes_bwd, int) or self.init_win_bytes_bwd < 0:
                raise FlowStatsError("Invalid backward initial window size")
            
            # Validate activity statistics
            if not isinstance(self.active_count, int) or self.active_count < 0:
                raise FlowStatsError("Invalid active count")
            
            if not isinstance(self.idle_count, int) or self.idle_count < 0:
                raise FlowStatsError("Invalid idle count")
            
            if not isinstance(self.active_time, (int, float)) or self.active_time < 0:
                raise FlowStatsError("Invalid active time")
            
            if not isinstance(self.idle_time, (int, float)) or self.idle_time < 0:
                raise FlowStatsError("Invalid idle time")
            
        except Exception as e:
            raise FlowStatsError(f"Invalid flow statistics: {str(e)}")


class Flow:
    """
    Class representing a network flow with associated metrics.
    
    Thread Safety Note:
    This class is not thread-safe on its own and should only be accessed
    while holding the FlowTracker's flow_lock. Do not expose Flow objects
    outside of FlowTracker's protected methods.
    """
    
    def __init__(self, flow_key: FlowKey, timestamp: float, activity_timeout: float):
        """
        Initialize flow.
        
        Args:
            flow_key: Flow key
            timestamp: Initial timestamp
            activity_timeout: Activity timeout in seconds
            
        Raises:
            FlowError: If initialization fails
            ValueError: If parameters are invalid
        """
        try:
            # Validate parameters
            if not isinstance(flow_key, FlowKey):
                raise ValueError("Invalid flow key")
            
            if not isinstance(timestamp, (int, float)) or timestamp <= 0:
                raise ValueError("Invalid timestamp")
            
            if not isinstance(activity_timeout, (int, float)) or activity_timeout <= 0:
                raise ValueError("Invalid activity timeout")
            
            # Initialize instance variables
            self.flow_key = flow_key
            self.start_time = timestamp
            self.last_update_time = timestamp
            self.activity_timeout = activity_timeout
            
            # Packet counts and sizes
            self.total_packets = 0
            self.total_bytes = 0
            self.fwd_packets = 0
            self.fwd_bytes = 0
            self.bwd_packets = 0
            self.bwd_bytes = 0
            
            # Packet length statistics
            self.fwd_pkt_len_max = 0
            self.fwd_pkt_len_min = float('inf')
            self.fwd_pkt_len_total = 0
            self.fwd_pkt_len_squared_sum = 0
            self.bwd_pkt_len_max = 0
            self.bwd_pkt_len_min = float('inf')
            self.bwd_pkt_len_total = 0
            self.bwd_pkt_len_squared_sum = 0
            
            # Inter-arrival time statistics
            self.fwd_iat_max = 0
            self.fwd_iat_min = float('inf')
            self.fwd_iat_total = 0
            self.fwd_iat_squared_sum = 0
            self.fwd_iat_count = 0
            self.fwd_last_timestamp = timestamp
            self.bwd_iat_max = 0
            self.bwd_iat_min = float('inf')
            self.bwd_iat_total = 0
            self.bwd_iat_squared_sum = 0
            self.bwd_iat_count = 0
            self.bwd_last_timestamp = timestamp
            
            # Flow IAT statistics
            self.flow_iat_max = 0
            self.flow_iat_min = float('inf')
            self.flow_iat_total = 0
            self.flow_iat_squared_sum = 0
            self.flow_iat_count = 0
            
            # Flag counts
            self.fin_count = 0
            self.syn_count = 0
            self.rst_count = 0
            self.psh_count = 0
            self.ack_count = 0
            self.urg_count = 0
            self.cwe_count = 0
            self.ece_count = 0
            
            # Window sizes
            self.init_win_bytes_fwd = 0
            self.init_win_bytes_bwd = 0
            
            # Activity statistics
            self.active_start = timestamp
            self.idle_start = 0
            self.active_count = 1
            self.idle_count = 0
            self.active_time = 0
            self.idle_time = 0
            
            # Debug information
            self.packets = []
            
        except Exception as e:
            raise FlowError(f"Failed to initialize flow: {str(e)}")
    
    def _determine_direction(self, packet: Dict[str, Any]) -> str:
        """
        Determine packet direction.
        
        Args:
            packet: Packet metadata dictionary
            
        Returns:
            "forward" or "backward"
            
        Raises:
            FlowError: If direction cannot be determined
            ValueError: If packet data is invalid
        """
        try:
            # Validate packet data
            if not isinstance(packet, dict):
                raise ValueError("Packet must be a dictionary")
            
            required_fields = ["src_ip", "dst_ip", "src_port", "dst_port"]
            for field in required_fields:
                if field not in packet:
                    raise ValueError(f"Missing required packet field: {field}")
            
            # Compare packet fields with flow key
            if (packet["src_ip"] == self.flow_key.src_ip and
                packet["src_port"] == self.flow_key.src_port and
                packet["dst_ip"] == self.flow_key.dst_ip and
                packet["dst_port"] == self.flow_key.dst_port):
                return "forward"
            elif (packet["src_ip"] == self.flow_key.dst_ip and
                  packet["src_port"] == self.flow_key.dst_port and
                  packet["dst_ip"] == self.flow_key.src_ip and
                  packet["dst_port"] == self.flow_key.src_port):
                return "backward"
            else:
                raise FlowError("Packet does not belong to this flow")
                
        except Exception as e:
            raise FlowError(f"Failed to determine packet direction: {str(e)}")
    
    def get_stats(self) -> FlowStats:
        """
        Get flow statistics.
        
        Returns:
            Flow statistics
            
        Raises:
            FlowError: If statistics cannot be computed
        """
        try:
            # Compute packet length statistics
            fwd_pkt_len_mean = (self.fwd_pkt_len_total / self.fwd_packets
                               if self.fwd_packets > 0 else 0)
            fwd_pkt_len_std = (math.sqrt(
                (self.fwd_pkt_len_squared_sum / self.fwd_packets) -
                (fwd_pkt_len_mean * fwd_pkt_len_mean)
            ) if self.fwd_packets > 0 else 0)
            
            bwd_pkt_len_mean = (self.bwd_pkt_len_total / self.bwd_packets
                               if self.bwd_packets > 0 else 0)
            bwd_pkt_len_std = (math.sqrt(
                (self.bwd_pkt_len_squared_sum / self.bwd_packets) -
                (bwd_pkt_len_mean * bwd_pkt_len_mean)
            ) if self.bwd_packets > 0 else 0)
            
            # Compute inter-arrival time statistics
            fwd_iat_mean = (self.fwd_iat_total / self.fwd_iat_count
                           if self.fwd_iat_count > 0 else 0)
            fwd_iat_std = (math.sqrt(
                (self.fwd_iat_squared_sum / self.fwd_iat_count) -
                (fwd_iat_mean * fwd_iat_mean)
            ) if self.fwd_iat_count > 0 else 0)
            
            bwd_iat_mean = (self.bwd_iat_total / self.bwd_iat_count
                           if self.bwd_iat_count > 0 else 0)
            bwd_iat_std = (math.sqrt(
                (self.bwd_iat_squared_sum / self.bwd_iat_count) -
                (bwd_iat_mean * bwd_iat_mean)
            ) if self.bwd_iat_count > 0 else 0)
            
            # Compute flow IAT statistics
            flow_iat_mean = (self.flow_iat_total / self.flow_iat_count
                            if self.flow_iat_count > 0 else 0)
            flow_iat_std = (math.sqrt(
                (self.flow_iat_squared_sum / self.flow_iat_count) -
                (flow_iat_mean * flow_iat_mean)
            ) if self.flow_iat_count > 0 else 0)
            
            # Create and return flow statistics
            return FlowStats(
                flow_key=self.flow_key,
                start_time=self.start_time,
                end_time=self.last_update_time,
                duration=self.last_update_time - self.start_time,
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                fwd_packets=self.fwd_packets,
                fwd_bytes=self.fwd_bytes,
                bwd_packets=self.bwd_packets,
                bwd_bytes=self.bwd_bytes,
                fwd_pkt_len_max=self.fwd_pkt_len_max,
                fwd_pkt_len_min=self.fwd_pkt_len_min if self.fwd_pkt_len_min != float('inf') else 0,
                fwd_pkt_len_mean=fwd_pkt_len_mean,
                fwd_pkt_len_std=fwd_pkt_len_std,
                bwd_pkt_len_max=self.bwd_pkt_len_max,
                bwd_pkt_len_min=self.bwd_pkt_len_min if self.bwd_pkt_len_min != float('inf') else 0,
                bwd_pkt_len_mean=bwd_pkt_len_mean,
                bwd_pkt_len_std=bwd_pkt_len_std,
                fwd_iat_max=self.fwd_iat_max,
                fwd_iat_min=self.fwd_iat_min if self.fwd_iat_min != float('inf') else 0,
                fwd_iat_mean=fwd_iat_mean,
                fwd_iat_std=fwd_iat_std,
                bwd_iat_max=self.bwd_iat_max,
                bwd_iat_min=self.bwd_iat_min if self.bwd_iat_min != float('inf') else 0,
                bwd_iat_mean=bwd_iat_mean,
                bwd_iat_std=bwd_iat_std,
                flow_iat_max=self.flow_iat_max,
                flow_iat_min=self.flow_iat_min if self.flow_iat_min != float('inf') else 0,
                flow_iat_mean=flow_iat_mean,
                flow_iat_std=flow_iat_std,
                fin_count=self.fin_count,
                syn_count=self.syn_count,
                rst_count=self.rst_count,
                psh_count=self.psh_count,
                ack_count=self.ack_count,
                urg_count=self.urg_count,
                cwe_count=self.cwe_count,
                ece_count=self.ece_count,
                init_win_bytes_fwd=self.init_win_bytes_fwd,
                init_win_bytes_bwd=self.init_win_bytes_bwd,
                active_count=self.active_count,
                idle_count=self.idle_count,
                active_time=self.active_time,
                idle_time=self.idle_time
            )
            
        except Exception as e:
            raise FlowError(f"Failed to compute flow statistics: {str(e)}")
    
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """
        Check if flow is expired.
        
        Args:
            current_time: Current timestamp
            timeout: Flow timeout in seconds
            
        Returns:
            True if flow is expired, False otherwise
            
        Raises:
            FlowError: If expiration check fails
            ValueError: If parameters are invalid
        """
        try:
            # Validate parameters
            if not isinstance(current_time, (int, float)) or current_time <= 0:
                raise ValueError("Invalid current time")
            
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                raise ValueError("Invalid timeout")
            
            # Check if flow is expired
            return current_time - self.last_update_time > timeout
            
        except Exception as e:
            raise FlowError(f"Failed to check flow expiration: {str(e)}")


class FlowTracker:
    """Enhanced flow tracker with comprehensive error handling."""
    
    def __init__(self, config: Any, logger: logging.Logger):
        """Initialize flow tracker with error handling."""
        try:
            self.config = config
            self.logger = logger
            self.flows: Dict[FlowKey, Flow] = {}
            self.flow_stats = FlowStats()
            self.last_cleanup = time.time()
            self.lock = threading.Lock()
            self.state_lock = threading.Lock()
            self.stats_lock = threading.Lock()
            self._is_initialized = False
            self._is_shutting_down = False
            self._error_count = 0
            self._warning_count = 0
            self._last_error_time = None
            self._last_warning_time = None
            self._stats = {
                'flow_creations': 0,
                'flow_updates': 0,
                'flow_timeouts': 0,
                'flow_cleanups': 0,
                'packet_processed': 0,
                'errors': defaultdict(int),
                'warnings': defaultdict(int),
                'validation_errors': defaultdict(int),
                'io_errors': defaultdict(int),
                'state_errors': defaultdict(int),
                'timeout_errors': defaultdict(int),
                'resource_errors': defaultdict(int)
            }
            
            # Validate configuration
            self._validate_config()
            
            # Initialize state
            self._initialize_state()
            
            self.logger.info("Flow tracker initialized successfully")
            
        except Exception as e:
            error_msg = f"Failed to initialize flow tracker: {str(e)}"
            self.logger.error(error_msg)
            raise FlowTrackerInitializationError(error_msg) from e

    def _validate_config(self) -> None:
        """Validate configuration settings."""
        try:
            required_settings = [
                'flow_timeout',
                'cleanup_interval',
                'max_flows',
                'max_packets_per_flow',
                'max_bytes_per_flow'
            ]
            
            for setting in required_settings:
                if not hasattr(self.config, setting):
                    raise FlowTrackerValidationError(f"Missing required configuration: {setting}")
                
                value = getattr(self.config, setting)
                if not isinstance(value, (int, float)) or value <= 0:
                    raise FlowTrackerValidationError(f"Invalid {setting} value: {value}")
                
        except FlowTrackerValidationError:
            raise
        except Exception as e:
            raise FlowTrackerValidationError(f"Configuration validation failed: {str(e)}") from e

    def _initialize_state(self) -> None:
        """Initialize flow tracker state."""
        try:
            with self.state_lock:
                if self._is_initialized:
                    raise FlowTrackerStateError("Flow tracker already initialized")
                
                self._is_initialized = True
                self._is_shutting_down = False
                self._error_count = 0
                self._warning_count = 0
                self._last_error_time = None
                self._last_warning_time = None
                
                # Initialize statistics
                with self.stats_lock:
                    for key in self._stats:
                        if isinstance(self._stats[key], defaultdict):
                            self._stats[key].clear()
                        else:
                            self._stats[key] = 0
                
        except Exception as e:
            raise FlowTrackerStateError(f"State initialization failed: {str(e)}") from e

    def _handle_error(self, error: Exception, context: str) -> None:
        """Centralized error handling with logging and statistics."""
        try:
            error_type = type(error).__name__
            error_msg = str(error)
            
            # Update error statistics
            with self.stats_lock:
                self._error_count += 1
                self._last_error_time = time.time()
                self._stats['errors'][error_type] += 1
                
                if isinstance(error, FlowTrackerValidationError):
                    self._stats['validation_errors'][context] += 1
                elif isinstance(error, FlowTrackerIOError):
                    self._stats['io_errors'][context] += 1
                elif isinstance(error, FlowTrackerStateError):
                    self._stats['state_errors'][context] += 1
                elif isinstance(error, FlowTrackerTimeoutError):
                    self._stats['timeout_errors'][context] += 1
                elif isinstance(error, FlowTrackerResourceError):
                    self._stats['resource_errors'][context] += 1
            
            # Log error
            self.logger.error(
                f"Error in {context}: {error_msg}",
                extra={
                    'error_type': error_type,
                    'context': context,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            # If error handling fails, log the original error and the handling error
            self.logger.critical(
                f"Error handling failed for {error}: {str(e)}",
                extra={
                    'original_error': str(error),
                    'handling_error': str(e),
                    'context': context,
                    'timestamp': datetime.now().isoformat()
                }
            )

    def _cleanup_expired_flows(self, current_time: float) -> None:
        """
        Clean up expired flows.
        
        Args:
            current_time: Current time in seconds
            
        Raises:
            FlowTrackerError: If cleanup fails
            ValueError: If current time is invalid
        """
        try:
            # Validate current time
            if not isinstance(current_time, (int, float)) or current_time < 0:
                raise ValueError("Invalid current time")
            
            # Get expired flows
            try:
                expired_flows = []
                with self.lock:
                    for flow_key, flow in self.flows.items():
                        try:
                            # Check if flow is expired
                            if flow.is_expired(current_time):
                                expired_flows.append(flow_key)
                                
                                # Finalize flow
                                try:
                                    flow.finalize()
                                    
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to finalize flow: {str(e)}",
                                        flow_key=flow_key.__dict__
                                    )
                                    self._stats['errors'][type(e).__name__] += 1
                                
                                # Export flow data
                                try:
                                    self._export_flow(flow.get_data())
                                    
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to export flow: {str(e)}",
                                        flow_key=flow_key.__dict__
                                    )
                                    self._stats['io_errors'][context] += 1
                                
                                # Update statistics
                                self._stats['flow_timeouts'] += 1
                                self._stats['active_flows'] -= 1
                                
                        except Exception as e:
                            self.logger.error(
                                f"Failed to check flow expiration: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to get expired flows: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return
            
            # Remove expired flows
            try:
                with self.lock:
                    for flow_key in expired_flows:
                        try:
                            del self.flows[flow_key]
                            
                        except Exception as e:
                            self.logger.error(
                                f"Failed to remove flow: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to remove expired flows: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to clean up expired flows: {str(e)}")
    
    def _cleanup_inactive_flows(self, current_time: float) -> None:
        """
        Clean up inactive flows.
        
        Args:
            current_time: Current time in seconds
            
        Raises:
            FlowTrackerError: If cleanup fails
            ValueError: If current time is invalid
        """
        try:
            # Validate current time
            if not isinstance(current_time, (int, float)) or current_time < 0:
                raise ValueError("Invalid current time")
            
            # Get inactive flows
            try:
                inactive_flows = []
                with self.lock:
                    for flow_key, flow in self.flows.items():
                        try:
                            # Check if flow is inactive
                            if flow.is_inactive(current_time):
                                inactive_flows.append(flow_key)
                                
                                # Finalize flow
                                try:
                                    flow.finalize()
                                    
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to finalize flow: {str(e)}",
                                        flow_key=flow_key.__dict__
                                    )
                                    self._stats['errors'][type(e).__name__] += 1
                                
                                # Export flow data
                                try:
                                    self._export_flow(flow.get_data())
                                    
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to export flow: {str(e)}",
                                        flow_key=flow_key.__dict__
                                    )
                                    self._stats['io_errors'][context] += 1
                                
                                # Update statistics
                                self._stats['flow_timeouts'] += 1
                                self._stats['active_flows'] -= 1
                                
                        except Exception as e:
                            self.logger.error(
                                f"Failed to check flow inactivity: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to get inactive flows: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return
            
            # Remove inactive flows
            try:
                with self.lock:
                    for flow_key in inactive_flows:
                        try:
                            del self.flows[flow_key]
                            
                        except Exception as e:
                            self.logger.error(
                                f"Failed to remove flow: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to remove inactive flows: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to clean up inactive flows: {str(e)}")
    
    def _cleanup_loop(self) -> None:
        """
        Run cleanup loop.
        
        Raises:
            FlowTrackerError: If cleanup loop fails
        """
        try:
            # Run cleanup loop
            while self.running:
                try:
                    # Get current time
                    try:
                        current_time = time.time()
                        
                    except Exception as e:
                        self.logger.error(f"Failed to get current time: {str(e)}")
                        self._stats['errors'][type(e).__name__] += 1
                        time.sleep(self.error_interval)
                        continue
                    
                    # Clean up expired flows
                    try:
                        self._cleanup_expired_flows(current_time)
                        
                    except Exception as e:
                        self.logger.error(f"Failed to clean up expired flows: {str(e)}")
                        self._stats['errors'][type(e).__name__] += 1
                    
                    # Clean up inactive flows
                    try:
                        self._cleanup_inactive_flows(current_time)
                        
                    except Exception as e:
                        self.logger.error(f"Failed to clean up inactive flows: {str(e)}")
                        self._stats['errors'][type(e).__name__] += 1
                    
                    # Sleep for cleanup interval
                    try:
                        time.sleep(self.cleanup_interval)
                        
                    except Exception as e:
                        self.logger.error(f"Failed to sleep: {str(e)}")
                        self._stats['errors'][type(e).__name__] += 1
                        time.sleep(self.error_interval)
                    
                except Exception as e:
                    self.logger.error(f"Failed to run cleanup loop: {str(e)}")
                    self._stats['errors'][type(e).__name__] += 1
                    time.sleep(self.error_interval)
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to run cleanup loop: {str(e)}")
    
    def _complete_flow(self, flow_key: FlowKey) -> None:
        """
        Complete a flow and remove it from tracking.
        
        Args:
            flow_key: Flow key
            
        Raises:
            FlowTrackerError: If completion fails
            ValueError: If flow key is invalid
        """
        try:
            # Validate flow key
            if not isinstance(flow_key, FlowKey):
                raise ValueError("Invalid flow key")
            
            # Get flow
            with self.lock:
                if flow_key not in self.flows:
                    self.logger.warning(f"Flow not found: {flow_key}")
                    return
                
                flow = self.flows[flow_key]
                
                # Finalize flow
                try:
                    flow.finalize(time.time())
                except Exception as e:
                    self.logger.error(f"Failed to finalize flow: {str(e)}")
                    self._stats['errors'][type(e).__name__] += 1
                
                # Remove flow
                try:
                    del self.flows[flow_key]
                    self._stats['flow_cleanups'] += 1
                except Exception as e:
                    self.logger.error(f"Failed to remove flow: {str(e)}")
                    self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to complete flow: {str(e)}")
    
    def _export_flow(self, flow_data: Dict[str, Any]) -> None:
        """
        Export flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Raises:
            FlowTrackerError: If export fails
            ValueError: If flow data is invalid
        """
        try:
            # Validate flow data
            if not isinstance(flow_data, dict):
                raise ValueError("Flow data must be a dictionary")
            
            required_fields = [
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                'packet_count', 'byte_count', 'duration'
            ]
            for field in required_fields:
                if field not in flow_data:
                    raise ValueError(f"Missing required flow data field: {field}")
            
            # Validate flow data fields
            src_ip = flow_data["src_ip"]
            if not isinstance(src_ip, str) or not src_ip:
                raise ValueError("Invalid source IP address")
            
            dst_ip = flow_data["dst_ip"]
            if not isinstance(dst_ip, str) or not dst_ip:
                raise ValueError("Invalid destination IP address")
            
            src_port = flow_data["src_port"]
            if not isinstance(src_port, int) or not (0 <= src_port <= 65535):
                raise ValueError("Invalid source port")
            
            dst_port = flow_data["dst_port"]
            if not isinstance(dst_port, int) or not (0 <= dst_port <= 65535):
                raise ValueError("Invalid destination port")
            
            protocol = flow_data["protocol"]
            if not isinstance(protocol, int) or not (0 <= protocol <= 255):
                raise ValueError("Invalid protocol number")
            
            packet_count = flow_data["packet_count"]
            if not isinstance(packet_count, int) or packet_count < 0:
                raise ValueError("Invalid packet count")
            
            byte_count = flow_data["byte_count"]
            if not isinstance(byte_count, int) or byte_count < 0:
                raise ValueError("Invalid byte count")
            
            duration = flow_data["duration"]
            if not isinstance(duration, (int, float)) or duration < 0:
                raise ValueError("Invalid duration")
            
            # Export flow data
            try:
                # Log flow data
                self.logger.info(
                    "Flow exported",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packet_count=packet_count,
                    byte_count=byte_count,
                    duration=duration
                )
                
                # Update statistics
                self._stats['flow_creations'] += 1
                self._stats['packet_processed'] += packet_count
                self._stats['total_bytes'] += byte_count
                
            except Exception as e:
                self.logger.error(f"Failed to export flow: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to export flow: {str(e)}")
    
    def process_packet(self, packet: Dict[str, Any]) -> None:
        """
        Process a network packet.
        
        Args:
            packet: Packet metadata dictionary
            
        Raises:
            FlowTrackerError: If processing fails
            ValueError: If packet data is invalid
        """
        try:
            # Validate packet data
            if not isinstance(packet, dict):
                raise ValueError("Packet data must be a dictionary")
            
            required_fields = [
                'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'length'
            ]
            for field in required_fields:
                if field not in packet:
                    raise ValueError(f"Missing required packet field: {field}")
            
            # Validate packet fields
            timestamp = packet["timestamp"]
            if not isinstance(timestamp, (int, float)) or timestamp < 0:
                raise ValueError("Invalid timestamp")
            
            src_ip = packet["src_ip"]
            if not isinstance(src_ip, str) or not src_ip:
                raise ValueError("Invalid source IP address")
            
            dst_ip = packet["dst_ip"]
            if not isinstance(dst_ip, str) or not dst_ip:
                raise ValueError("Invalid destination IP address")
            
            src_port = packet["src_port"]
            if not isinstance(src_port, int) or not (0 <= src_port <= 65535):
                raise ValueError("Invalid source port")
            
            dst_port = packet["dst_port"]
            if not isinstance(dst_port, int) or not (0 <= dst_port <= 65535):
                raise ValueError("Invalid destination port")
            
            protocol = packet["protocol"]
            if not isinstance(protocol, int) or not (0 <= protocol <= 255):
                raise ValueError("Invalid protocol number")
            
            length = packet["length"]
            if not isinstance(length, int) or length < 0:
                raise ValueError("Invalid packet length")
            
            # Update flow tracker
            try:
                self.update(packet)
                
            except Exception as e:
                self.logger.error(f"Failed to update flow tracker: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to process packet: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics in a thread-safe manner."""
        try:
            with self.stats_lock:
                return {
                    'flow_creations': self._stats['flow_creations'],
                    'flow_updates': self._stats['flow_updates'],
                    'flow_timeouts': self._stats['flow_timeouts'],
                    'flow_cleanups': self._stats['flow_cleanups'],
                    'packet_processed': self._stats['packet_processed'],
                    'error_count': self._error_count,
                    'warning_count': self._warning_count,
                    'last_error_time': self._last_error_time,
                    'last_warning_time': self._last_warning_time,
                    'errors': dict(self._stats['errors']),
                    'warnings': dict(self._stats['warnings']),
                    'validation_errors': dict(self._stats['validation_errors']),
                    'io_errors': dict(self._stats['io_errors']),
                    'state_errors': dict(self._stats['state_errors']),
                    'timeout_errors': dict(self._stats['timeout_errors']),
                    'resource_errors': dict(self._stats['resource_errors'])
                }
        except Exception as e:
            self._handle_error(e, "statistics retrieval")
            return {}
    
    def get_flow_stats(self, flow_key: FlowKey) -> Optional[FlowStats]:
        """
        Get statistics for a specific flow.
        
        Args:
            flow_key: Flow key
            
        Returns:
            Flow statistics if flow exists, None otherwise
            
        Raises:
            FlowTrackerError: If flow statistics cannot be retrieved
            ValueError: If flow key is invalid
        """
        try:
            # Validate flow key
            if not isinstance(flow_key, FlowKey):
                raise ValueError("Invalid flow key")
            
            with self.lock:
                if flow_key in self.flows:
                    try:
                        return self.flows[flow_key].get_stats()
                    except Exception as e:
                        self.logger.error(f"Failed to get flow statistics: {str(e)}")
                        return None
                return None
                
        except Exception as e:
            raise FlowTrackerError(f"Failed to get flow statistics: {str(e)}")
    
    def get_all_flow_stats(self) -> List[FlowStats]:
        """
        Get statistics for all flows.
        
        Returns:
            List of flow statistics
            
        Raises:
            FlowTrackerError: If flow statistics cannot be retrieved
        """
        try:
            flow_stats = []
            with self.lock:
                for flow in self.flows.values():
                    try:
                        stats = flow.get_stats()
                        if stats is not None:
                            flow_stats.append(stats)
                    except Exception as e:
                        self.logger.error(f"Failed to get flow statistics: {str(e)}")
                        continue
            return flow_stats
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to get all flow statistics: {str(e)}")
    
    def get_active_flow_count(self) -> int:
        """
        Get active flow count.
        
        Returns:
            Number of active flows
            
        Raises:
            FlowTrackerError: If flow count retrieval fails
        """
        try:
            # Get active flow count
            try:
                with self.lock:
                    return len(self.flows)
                
            except Exception as e:
                self.logger.error(f"Failed to get active flow count: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return 0
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to get active flow count: {str(e)}")
    
    def get_total_flow_count(self) -> int:
        """
        Get total flow count.
        
        Returns:
            Number of total flows
            
        Raises:
            FlowTrackerError: If flow count retrieval fails
        """
        try:
            # Get total flow count
            try:
                with self.lock:
                    return self._stats['flow_creations']
                
            except Exception as e:
                self.logger.error(f"Failed to get total flow count: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return 0
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to get total flow count: {str(e)}")
    
    def get_error_count(self) -> int:
        """
        Get error count.
        
        Returns:
            Number of errors
            
        Raises:
            FlowTrackerError: If error count retrieval fails
        """
        try:
            # Get error count
            try:
                with self.lock:
                    return self._stats['errors'][type(e).__name__]
                
            except Exception as e:
                self.logger.error(f"Failed to get error count: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return 0
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to get error count: {str(e)}")
    
    def start(self) -> None:
        """
        Start flow tracker.
        
        Raises:
            FlowTrackerError: If flow tracker fails to start
        """
        try:
            # Check if flow tracker is already running
            if self.running:
                self.logger.warning("Flow tracker is already running")
                return
            
            # Start flow tracker
            try:
                # Initialize statistics
                self._stats = {
                    'flow_creations': 0,
                    'flow_updates': 0,
                    'flow_timeouts': 0,
                    'flow_cleanups': 0,
                    'packet_processed': 0,
                    'errors': defaultdict(int),
                    'warnings': defaultdict(int),
                    'validation_errors': defaultdict(int),
                    'io_errors': defaultdict(int),
                    'state_errors': defaultdict(int),
                    'timeout_errors': defaultdict(int),
                    'resource_errors': defaultdict(int)
                }
                
                # Start cleanup thread
                self.running = True
                self.cleanup_thread = threading.Thread(
                    target=self._cleanup_loop,
                    name="flow_tracker_cleanup"
                )
                self.cleanup_thread.daemon = True
                self.cleanup_thread.start()
                
                # Log startup
                self.logger.info(
                    "Flow tracker started",
                    max_flows=self.max_flows,
                    activity_timeout=self.activity_timeout,
                    cleanup_interval=self.cleanup_interval
                )
                
            except Exception as e:
                self.logger.error(f"Failed to start flow tracker: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                self.running = False
                raise FlowTrackerError(f"Failed to start flow tracker: {str(e)}")
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to start flow tracker: {str(e)}")
    
    def stop(self) -> None:
        """
        Stop flow tracker.
        
        Raises:
            FlowTrackerError: If flow tracker fails to stop
        """
        try:
            # Check if flow tracker is already stopped
            if not self.running:
                self.logger.warning("Flow tracker is already stopped")
                return
            
            # Stop flow tracker
            try:
                # Stop cleanup thread
                self.running = False
                if self.cleanup_thread is not None:
                    self.cleanup_thread.join(timeout=self.cleanup_interval)
                    self.cleanup_thread = None
                
                # Finalize all active flows
                with self.lock:
                    current_time = time.time()
                    for flow_key in list(self.flows.keys()):
                        try:
                            # Get flow
                            flow = self.flows[flow_key]
                            
                            # Finalize flow
                            flow.finalize()
                            
                            # Export flow data
                            self._export_flow(flow.get_data())
                            
                            # Update statistics
                            self._stats['flow_timeouts'] += 1
                            self._stats['active_flows'] -= 1
                            
                            # Remove flow
                            del self.flows[flow_key]
                            
                        except Exception as e:
                            self.logger.error(
                                f"Failed to finalize flow: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                
                # Log shutdown
                self.logger.info(
                    "Flow tracker stopped",
                    total_flows=self._stats['flow_creations'],
                    flow_timeouts=self._stats['flow_timeouts'],
                    errors=self._stats['errors'][type(e).__name__]
                )
                
            except Exception as e:
                self.logger.error(f"Failed to stop flow tracker: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                raise FlowTrackerError(f"Failed to stop flow tracker: {str(e)}")
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to stop flow tracker: {str(e)}")

    def update(self, packet: Dict[str, Any]) -> None:
        """Update flow tracker with new packet data."""
        try:
            # Validate packet data
            self._validate_packet(packet)
            
            # Create flow key
            flow_key = self._create_flow_key(packet)
            
            # Update flow
            with self.lock:
                if flow_key in self.flows:
                    flow = self.flows[flow_key]
                    try:
                        flow.update(packet)
                        self._update_stats('flow_updates')
                    except Exception as e:
                        self._handle_error(e, f"flow update for {flow_key}")
                else:
                    try:
                        if len(self.flows) >= self.config.max_flows:
                            raise FlowTrackerResourceError("Maximum number of flows reached")
                        
                        self.flows[flow_key] = Flow(
                            flow_key=flow_key,
                            timestamp=packet['timestamp'],
                            activity_timeout=self.config.flow_timeout
                        )
                        self.logger.error(f"Failed to update flow: {str(e)}")
                        self._stats['errors'][type(e).__name__] += 1
                    except Exception as e:
                        self._handle_error(e, "flow creation")
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to update flow tracker: {str(e)}")

    def _cleanup(self) -> None:
        """
        Clean up expired flows.
        
        Raises:
            FlowTrackerError: If cleanup fails
        """
        try:
            # Get current time
            try:
                current_time = time.time()
                
            except Exception as e:
                self.logger.error(f"Failed to get current time: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return
            
            # Clean up expired flows
            try:
                with self.lock:
                    expired_flows = []
                    for flow_key, flow in self.flows.items():
                        try:
                            # Check if flow is expired
                            if flow.is_expired(current_time):
                                expired_flows.append(flow_key)
                                
                                # Finalize flow
                                try:
                                    flow.finalize()
                                    
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to finalize flow: {str(e)}",
                                        flow_key=flow_key.__dict__
                                    )
                                    self._stats['errors'][type(e).__name__] += 1
                                
                                # Export flow data
                                try:
                                    self._export_flow(flow.get_data())
                                    
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to export flow: {str(e)}",
                                        flow_key=flow_key.__dict__
                                    )
                                    self._stats['io_errors'][context] += 1
                                
                                # Update statistics
                                self._stats['flow_timeouts'] += 1
                                self._stats['active_flows'] -= 1
                                
                        except Exception as e:
                            self.logger.error(
                                f"Failed to check flow expiration: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                    
                    # Remove expired flows
                    for flow_key in expired_flows:
                        try:
                            del self.flows[flow_key]
                            
                        except Exception as e:
                            self.logger.error(
                                f"Failed to remove flow: {str(e)}",
                                flow_key=flow_key.__dict__
                            )
                            self._stats['errors'][type(e).__name__] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to clean up flows: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to clean up flows: {str(e)}")

    def run(self) -> None:
        """
        Run the flow tracker.
        
        Raises:
            FlowTrackerError: If flow tracker fails to run
        """
        try:
            # Start flow tracker
            try:
                self.start()
                
            except Exception as e:
                self.logger.error(f"Failed to start flow tracker: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return
            
            # Run flow tracker
            try:
                while self.running:
                    try:
                        # Clean up expired flows
                        self._cleanup()
                        
                        # Sleep for cleanup interval
                        time.sleep(self.cleanup_interval)
                        
                    except Exception as e:
                        self.logger.error(f"Failed to run flow tracker: {str(e)}")
                        self._stats['errors'][type(e).__name__] += 1
                        
                        # Check if flow tracker should stop
                        if not self.running:
                            break
                        
                        # Sleep for error interval
                        time.sleep(self.error_interval)
                
            except Exception as e:
                self.logger.error(f"Failed to run flow tracker: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
            # Stop flow tracker
            try:
                self.stop()
                
            except Exception as e:
                self.logger.error(f"Failed to stop flow tracker: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to run flow tracker: {str(e)}")

    def get_flow(self, flow_key: FlowKey) -> Optional[Flow]:
        """
        Get flow by key.
        
        Args:
            flow_key: Flow key
            
        Returns:
            Flow if found, None otherwise
            
        Raises:
            FlowTrackerError: If flow retrieval fails
            ValueError: If flow key is invalid
        """
        try:
            # Validate flow key
            if not isinstance(flow_key, FlowKey):
                raise ValueError("Invalid flow key type")
            
            # Get flow
            try:
                with self.lock:
                    if flow_key not in self.flows:
                        self.logger.warning(
                            "Flow not found",
                            flow_key=flow_key.__dict__
                        )
                        return None
                    
                    return self.flows[flow_key]
                
            except Exception as e:
                self.logger.error(f"Failed to get flow: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return None
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to get flow: {str(e)}")

    def get_flow_stats(self) -> List[Dict[str, Any]]:
        """
        Get flow statistics.
        
        Returns:
            List of flow statistics dictionaries
            
        Raises:
            FlowTrackerError: If statistics retrieval fails
        """
        try:
            # Get flow statistics
            try:
                flow_stats = []
                with self.lock:
                    for flow in self.flows.values():
                        try:
                            # Get flow data
                            flow_data = flow.get_data()
                            
                            # Add flow statistics
                            flow_stats.append({
                                'src_ip': flow_data['src_ip'],
                                'dst_ip': flow_data['dst_ip'],
                                'src_port': flow_data['src_port'],
                                'dst_port': flow_data['dst_port'],
                                'protocol': flow_data['protocol'],
                                'packet_count': flow_data['packet_count'],
                                'byte_count': flow_data['byte_count'],
                                'duration': flow_data['duration'],
                                'start_time': flow_data['start_time'],
                                'end_time': flow_data['end_time'],
                                'flags': flow_data['flags']
                            })
                            
                        except Exception as e:
                            self.logger.error(f"Failed to get flow data: {str(e)}")
                            self._stats['errors'][type(e).__name__] += 1
                
                return flow_stats
                
            except Exception as e:
                self.logger.error(f"Failed to get flow statistics: {str(e)}")
                self._stats['errors'][type(e).__name__] += 1
                return []
            
        except Exception as e:
            raise FlowTrackerError(f"Failed to get flow statistics: {str(e)}")

    def cleanup(self, current_time: float) -> None:
        """Clean up expired flows."""
        try:
            with self.lock:
                expired_flows = []
                for flow_key, flow in self.flows.items():
                    try:
                        if flow.is_expired(current_time):
                            expired_flows.append(flow_key)
                            self._update_stats('flow_timeouts')
                    except Exception as e:
                        self._handle_error(e, f"flow expiration check for {flow_key}")
                
                # Remove expired flows
                for flow_key in expired_flows:
                    try:
                        del self.flows[flow_key]
                        self._update_stats('flow_cleanups')
                    except Exception as e:
                        self._handle_error(e, f"flow removal for {flow_key}")
                
                self.last_cleanup = current_time
                
        except Exception as e:
            self._handle_error(e, "flow cleanup")

    def get_all_flows(self) -> Dict[FlowKey, Flow]:
        """Get all active flows."""
        try:
            with self.lock:
                return self.flows.copy()
        except Exception as e:
            self._handle_error(e, "all flows retrieval")
            return {}

    def shutdown(self) -> None:
        """Shutdown flow tracker."""
        try:
            with self.state_lock:
                if self._is_shutting_down:
                    return
                
                self._is_shutting_down = True
                
            # Final cleanup
            self.cleanup(time.time())
            
            # Log final statistics
            stats = self.get_stats()
            self.logger.info(
                "Flow tracker shutdown complete",
                extra={
                    'final_stats': stats,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            self._handle_error(e, "flow tracker shutdown")
            raise FlowTrackerCleanupError(f"Shutdown failed: {str(e)}") from e

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
