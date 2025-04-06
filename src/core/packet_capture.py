"""
Packet Capture module for the Network Feature Extractor.
Loads and interacts with the eBPF program for packet capture with enhanced error handling and resource management.
"""

import os
import ctypes
import threading
import queue
import time
import socket
import select
import random
import errno
import struct
import signal
import resource
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from enum import IntEnum, auto
from contextlib import contextmanager

from bcc import BPF
import pyroute2
from structlog import get_logger

# Import local modules
from .config import Config
from ..logging.logger import Logger

class CaptureError(Exception):
    """Base exception for packet capture errors."""
    pass

class CaptureInitializationError(CaptureError):
    """Exception raised during capture initialization."""
    pass

class CaptureCleanupError(CaptureError):
    """Exception raised during capture cleanup."""
    pass

class CaptureStatsError(CaptureError):
    """Exception raised during statistics collection."""
    pass

class CaptureConfigError(CaptureError):
    """Exception raised during configuration validation."""
    pass

class CaptureStateError(CaptureError):
    """Exception raised during state management."""
    pass

class CaptureMode(IntEnum):
    """Enum for capture modes."""
    XDP = auto()
    RAW_SOCKET = auto()

class OverflowPolicy(IntEnum):
    """Enum for queue overflow policies."""
    DROP = auto()
    BLOCK = auto()

@dataclass
class CaptureConfig:
    """Configuration for packet capture."""
    interface: str
    mode: CaptureMode = CaptureMode.XDP
    sample_rate: float = 1.0
    ebpf_path: Optional[str] = None
    packet_queue_size: int = 100000
    overflow_policy: OverflowPolicy = OverflowPolicy.DROP
    promiscuous_mode: bool = True
    buffer_size: int = 65535
    timeout_ms: int = 1000

    def validate(self) -> None:
        """Validate configuration values."""
        try:
            if not os.path.exists(f"/sys/class/net/{self.interface}"):
                raise CaptureConfigError(f"Interface {self.interface} does not exist")
            
            if not 0.0 <= self.sample_rate <= 1.0:
                raise CaptureConfigError("Sample rate must be between 0.0 and 1.0")
            
            if self.packet_queue_size <= 0:
                raise CaptureConfigError("Queue size must be positive")
            
            if self.buffer_size <= 0:
                raise CaptureConfigError("Buffer size must be positive")
            
            if self.timeout_ms <= 0:
                raise CaptureConfigError("Timeout must be positive")
            
            if self.ebpf_path and not os.path.exists(self.ebpf_path):
                raise CaptureConfigError(f"eBPF program path {self.ebpf_path} does not exist")
                
        except Exception as e:
            raise CaptureConfigError(f"Configuration validation failed: {str(e)}")

@dataclass
class CaptureStats:
    """Statistics for packet capture."""
    processed_packets: int = 0
    dropped_packets: int = 0
    queue_overflow: int = 0
    startup_errors: int = 0
    processing_errors: int = 0
    fatal_errors: int = 0
    captured_packets: int = 0
    callback_errors: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    last_update_time: float = 0.0
    error_count: int = 0
    recovery_count: int = 0
    state_changes: int = 0

    def validate(self) -> None:
        """Validate statistics values."""
        try:
            if any(value < 0 for value in [
                self.processed_packets,
                self.dropped_packets,
                self.queue_overflow,
                self.startup_errors,
                self.processing_errors,
                self.fatal_errors,
                self.captured_packets,
                self.callback_errors,
                self.memory_usage_mb,
                self.cpu_usage_percent,
                self.error_count,
                self.recovery_count,
                self.state_changes
            ]):
                raise CaptureStatsError("Statistics values cannot be negative")
            
            if not 0.0 <= self.cpu_usage_percent <= 100.0:
                raise CaptureStatsError("CPU usage must be between 0 and 100 percent")
                
        except Exception as e:
            raise CaptureStatsError(f"Statistics validation failed: {str(e)}")

class PacketCapture:
    """Enhanced packet capture module using eBPF with improved error handling and resource management."""

    def __init__(self, config: CaptureConfig, logger: Logger):
        """
        Initialize packet capture with configuration and logging.
        
        Args:
            config: Capture configuration
            logger: Logger instance
            
        Raises:
            CaptureInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger.get_logger()
            
            # Validate configuration
            self.config.validate()
            
            # State variables with error handling
            self.running = False
            self.processing_active = False
            self.bpf = None
            self.raw_socket = None
            self.callback = None
            self.processing_thread = None
            self.cleanup_thread = None
            self.state_lock = threading.RLock()
            
            # Packet queue with memory monitoring
            try:
                self.packet_queue = queue.Queue(maxsize=config.packet_queue_size)
            except Exception as e:
                raise CaptureInitializationError(f"Failed to create packet queue: {str(e)}")
            
            # Statistics with thread-safe updates
            self.stats = CaptureStats()
            self.stats_lock = threading.RLock()
            
            # Resource monitoring
            self.memory_limit_mb = 1024  # Default 1GB limit
            self.cpu_limit_percent = 80  # Default 80% CPU limit
            
            # Error recovery
            self.error_count = 0
            self.max_errors = 10
            self.error_window_seconds = 60
            
            # Performance monitoring
            self.last_stats_time = time.time()
            self.stats_interval = 5.0  # seconds
            
            self.logger.info(
                "Packet capture initialized",
                interface=config.interface,
                mode=config.mode.name,
                sample_rate=config.sample_rate
            )
            
        except Exception as e:
            raise CaptureInitializationError(f"Failed to initialize packet capture: {str(e)}")
    
    def _validate_state(self) -> None:
        """Validate current state of the capture."""
        try:
            with self.state_lock:
                if self.running and not self.processing_thread:
                    raise CaptureStateError("Running state but no processing thread")
                if self.processing_active and not self.running:
                    raise CaptureStateError("Processing active but not running")
                if self.bpf and not self.running:
                    raise CaptureStateError("BPF program loaded but not running")
                if self.raw_socket and not self.running:
                    raise CaptureStateError("Raw socket open but not running")
        except Exception as e:
            raise CaptureStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """Update capture state with error handling."""
        try:
            with self.state_lock:
                old_state = self.running
                self.running = new_state
                self.stats.state_changes += 1
                
                if old_state != new_state:
                    self.logger.info(
                        "Capture state changed",
                        old_state=old_state,
                        new_state=new_state
                    )
        except Exception as e:
            raise CaptureStateError(f"Failed to update state: {str(e)}")
    
    def _cleanup_resources(self) -> None:
        """Cleanup resources with error handling."""
        try:
            # Cleanup BPF program
            if self.bpf:
                try:
                    self.bpf.cleanup()
                    self.bpf = None
                except Exception as e:
                    self.logger.error("Failed to cleanup BPF program", error=str(e))
            
            # Cleanup raw socket
            if self.raw_socket:
                try:
                    self.raw_socket.close()
                    self.raw_socket = None
                except Exception as e:
                    self.logger.error("Failed to cleanup raw socket", error=str(e))
            
            # Cleanup processing thread
            if self.processing_thread:
                try:
                    self.processing_thread.join(timeout=5.0)
                    if self.processing_thread.is_alive():
                        self.logger.warning("Processing thread did not terminate cleanly")
                except Exception as e:
                    self.logger.error("Failed to cleanup processing thread", error=str(e))
            
            # Cleanup cleanup thread
            if self.cleanup_thread:
                try:
                    self.cleanup_thread.join(timeout=5.0)
                    if self.cleanup_thread.is_alive():
                        self.logger.warning("Cleanup thread did not terminate cleanly")
                except Exception as e:
                    self.logger.error("Failed to cleanup cleanup thread", error=str(e))
            
            # Clear queue
            try:
                while not self.packet_queue.empty():
                    self.packet_queue.get_nowait()
            except Exception as e:
                self.logger.error("Failed to clear packet queue", error=str(e))
            
        except Exception as e:
            raise CaptureCleanupError(f"Resource cleanup failed: {str(e)}")
    
    def _update_stats(self, stat_name: str, value: int = 1) -> None:
        """Update statistics in a thread-safe manner with error handling."""
        try:
            with self.stats_lock:
                current_value = getattr(self.stats, stat_name)
                setattr(self.stats, stat_name, current_value + value)
                self.stats.last_update_time = time.time()
                self.stats.validate()
        except Exception as e:
            raise CaptureStatsError(f"Failed to update statistics: {str(e)}")
    
    def _monitor_resources(self) -> None:
        """Monitor system resources with error handling."""
        try:
            # Get memory usage
            try:
                memory_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
            except Exception as e:
                self.logger.error("Failed to get memory usage", error=str(e))
                return
            
            # Update stats
            try:
                with self.stats_lock:
                    self.stats.memory_usage_mb = memory_mb
                    self.stats.validate()
            except Exception as e:
                self.logger.error("Failed to update memory stats", error=str(e))
            
            # Check memory limit
            if memory_mb > self.memory_limit_mb:
                self.logger.warning(
                    "Memory usage exceeded limit",
                    current_mb=memory_mb,
                    limit_mb=self.memory_limit_mb
                )
                # Reduce queue size if possible
                if self.packet_queue.maxsize > 1000:
                    try:
                        new_size = max(1000, self.packet_queue.maxsize // 2)
                        self.packet_queue = queue.Queue(maxsize=new_size)
                        self.logger.info(
                            "Reduced queue size due to memory pressure",
                            new_size=new_size
                        )
                    except Exception as e:
                        self.logger.error("Failed to reduce queue size", error=str(e))
            
            # Log statistics periodically
            current_time = time.time()
            if current_time - self.last_stats_time >= self.stats_interval:
                try:
                    self.logger.info(
                        "Capture statistics",
                        stats=self.stats.__dict__,
                        queue_size=self.packet_queue.qsize()
                    )
                    self.last_stats_time = current_time
                except Exception as e:
                    self.logger.error("Failed to log statistics", error=str(e))
                
        except Exception as e:
            self.logger.error("Error monitoring resources", error=str(e))
    
    def _handle_error(self, error: Exception, context: str,
                     severity: str = "error", stat_key: str = "processing_errors",
                     recover_action: Optional[Callable] = None) -> None:
        """
        Handle errors with recovery options and error handling.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            severity: Error severity ('error' or 'warning')
            stat_key: Statistics key to update
            recover_action: Optional recovery function
            
        Raises:
            CaptureError: If error handling fails
        """
        try:
            # Update error statistics
            self._update_stats(stat_key)
            self.error_count += 1
            
            # Log error
            log_method = getattr(self.logger, severity)
            log_method(
                f"Error in {context}",
                error=str(error),
                error_count=self.error_count
            )
            
            # Check if we need to recover
            if self.error_count >= self.max_errors:
                self.logger.error(
                    "Maximum error count reached",
                    error_count=self.error_count,
                    max_errors=self.max_errors
                )
                if recover_action:
                    try:
                        recover_action()
                        self.stats.recovery_count += 1
                    except Exception as e:
                        raise CaptureError(f"Recovery action failed: {str(e)}")
                else:
                    self.stop()
            
            # Reset error count after error window
            if time.time() - self.last_stats_time > self.error_window_seconds:
                self.error_count = 0
                
        except Exception as e:
            raise CaptureError(f"Error handling failed: {str(e)}")
    
    def start(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """
        Start packet capture with enhanced error handling.
        
        Args:
            callback: Callback function to process packet metadata
            
        Returns:
            True if capture started successfully, False otherwise
            
        Raises:
            CaptureError: If start operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.running:
                self.logger.warning("Capture already running")
                return True
            
            # Set callback
            self.callback = callback
            
            # Start capture based on mode
            success = False
            if self.config.mode == CaptureMode.XDP:
                success = self._start_xdp_capture()
            else:
                success = self._start_raw_socket_capture()
            
            if success:
                self._update_state(True)
                self.logger.info("Packet capture started successfully")
            else:
                self._handle_error(
                    CaptureError("Failed to start capture"),
                    "start",
                    "error",
                    "startup_errors"
                )
            
            return success
            
        except Exception as e:
            self._handle_error(e, "start", "error", "startup_errors")
            return False
    
    def _start_xdp_capture(self) -> bool:
        """Start XDP capture with enhanced error handling."""
        try:
            # Load and compile eBPF program
            bpf_text = self._load_ebpf_program()
            sampling_rate_int = int(self.config.sample_rate * 100)
            bpf_text = bpf_text.replace("SAMPLING_RATE", str(sampling_rate_int))
            
            self.bpf = BPF(text=bpf_text)
            
            # Attach XDP program
            self.bpf.attach_xdp(
                self.config.interface,
                self.bpf.load_func("xdp_packet_capture", BPF.XDP)
            )
            
            # Set up ring buffer
            self.bpf["metadata_ringbuf"].open_ring_buffer(
                self._ring_buffer_callback
            )
            
            # Start ring buffer polling
            threading.Thread(
                target=self._poll_ring_buffer,
                daemon=True
            ).start()
            
            self.logger.info(
                "XDP capture started",
                interface=self.config.interface
            )
            
            return True
            
        except Exception as e:
            self._handle_error(
                e,
                "_start_xdp_capture",
                "error",
                "startup_errors"
            )
            return False
    
    def _start_raw_socket_capture(self) -> bool:
        """Start raw socket capture with enhanced error handling."""
        try:
            # Create and configure raw socket
            self.raw_socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(0x0003)
            )
            
            # Set socket options
            self.raw_socket.setblocking(False)
            self.raw_socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_RCVBUF,
                self.config.buffer_size
            )
            
            # Bind to interface
            self.raw_socket.bind((self.config.interface, 0))
            
            # Set promiscuous mode if configured
            if self.config.promiscuous_mode:
                self._set_promiscuous_mode(self.config.interface, True)
            
            # Start socket polling
            threading.Thread(
                target=self._poll_raw_socket,
                daemon=True
            ).start()
            
            self.logger.info(
                "Raw socket capture started",
                interface=self.config.interface
            )
            
            return True
            
        except Exception as e:
            self._handle_error(
                e,
                "_start_raw_socket_capture",
                "error",
                "startup_errors"
            )
            return False
    
    def stop(self) -> None:
        """
        Stop packet capture with enhanced error handling.
        
        Raises:
            CaptureError: If stop operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                self.logger.warning("Capture already stopped")
                return
            
            # Update state first to prevent new packets
            self._update_state(False)
            
            # Cleanup resources
            self._cleanup_resources()
            
            self.logger.info("Packet capture stopped successfully")
            
        except Exception as e:
            self._handle_error(e, "stop", "error", "fatal_errors")
            raise CaptureError(f"Failed to stop capture: {str(e)}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current statistics with error handling.
        
        Returns:
            Dictionary of statistics
            
        Raises:
            CaptureStatsError: If statistics retrieval fails
        """
        try:
            with self.stats_lock:
                stats_dict = self.stats.__dict__.copy()
                stats_dict["queue_size"] = self.packet_queue.qsize()
                self.stats.validate()
                return stats_dict
        except Exception as e:
            raise CaptureStatsError(f"Failed to get statistics: {str(e)}")
    
    def is_running(self) -> bool:
        """
        Check if capture is running with error handling.
        
        Returns:
            True if running, False otherwise
            
        Raises:
            CaptureStateError: If state check fails
        """
        try:
            with self.state_lock:
                return self.running
        except Exception as e:
            raise CaptureStateError(f"Failed to check running state: {str(e)}")
