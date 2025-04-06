"""
System Statistics Monitoring module for the Network Feature Extractor.
Collects and monitors system resource usage with enhanced error handling and performance monitoring.
"""

import time
import threading
import psutil
import socket
import platform
import sys
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from structlog import get_logger

from ..core.config import Config
from ..logging.logger import Logger


class SystemStatsError(Exception):
    """Base exception for system statistics errors."""
    pass

class SystemStatsInitializationError(SystemStatsError):
    """Raised when system stats initialization fails."""
    pass

class SystemStatsCleanupError(SystemStatsError):
    """Raised when system stats cleanup fails."""
    pass

class SystemStatsStateError(SystemStatsError):
    """Raised when system stats is in an invalid state."""
    pass

class SystemStatsValidationError(SystemStatsError):
    """Raised when system stats validation fails."""
    pass

class SystemStatsIOError(SystemStatsError):
    """Raised when I/O operations fail."""
    pass

class SystemStatsResourceError(SystemStatsError):
    """Raised when resource collection fails."""
    pass

class SystemStatsTimeoutError(SystemStatsError):
    """Raised when operations timeout."""
    pass

class ResourceType(Enum):
    """Enum for resource types."""
    CPU = 'cpu'
    MEMORY = 'memory'
    DISK = 'disk'
    NETWORK = 'network'
    PROCESS = 'process'
    SYSTEM = 'system'


@dataclass
class ResourceStats:
    """Resource statistics data class."""
    type: ResourceType
    timestamp: float
    values: Dict[str, Any]
    error: Optional[str] = None


@dataclass
class SystemStats:
    """System statistics data class."""
    # CPU statistics
    cpu_percent: float
    cpu_count: int
    cpu_freq: Dict[str, float]
    cpu_load: List[float]
    cpu_times: Dict[str, float]
    
    # Memory statistics
    memory_total: int
    memory_available: int
    memory_used: int
    memory_percent: float
    swap_total: int
    swap_used: int
    swap_percent: float
    
    # Disk statistics
    disk_usage: Dict[str, Dict[str, Any]]
    disk_io: Dict[str, Dict[str, int]]
    
    # Network statistics
    network_io: Dict[str, Dict[str, int]]
    network_connections: int
    network_addresses: Dict[str, List[Dict[str, str]]]
    
    # Process statistics
    process_count: int
    thread_count: int
    handle_count: int
    process_memory: Dict[str, int]
    
    # System information
    boot_time: float
    uptime: float
    hostname: str
    platform: str
    python_version: str
    system_load: List[float]
    
    # Performance metrics
    collection_time: float
    error_count: int = 0
    warnings: List[str] = field(default_factory=list)


class SystemStatsCollector:
    """
    System statistics collector.
    Collects system resource usage statistics at regular intervals with enhanced monitoring.
    """
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the system statistics collector.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            
        Raises:
            SystemStatsInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger_manager.get_logger()
            
            # Get monitoring configuration
            self.monitoring_config = self.config.get('monitoring', {})
            self.system_stats_config = self.monitoring_config.get('system_stats', {})
            
            # Check if system stats collection is enabled
            self.enabled = self.system_stats_config.get('enabled', False)
            self.collection_interval = self.system_stats_config.get('interval', 10)
            
            # Initialize state
            self.running = False
            self.collection_thread = None
            self.current_stats = None
            self.stats_lock = threading.RLock()
            self.state_lock = threading.RLock()
            self._is_initialized = False
            self._is_shutting_down = False
            
            # Initialize statistics
            self.stats = {
                "collection_errors": 0,
                "last_collection_time": 0,
                "total_collections": 0,
                "total_errors": 0,
                "total_warnings": 0,
                "collection_times": [],
                "resource_errors": {
                    ResourceType.CPU: 0,
                    ResourceType.MEMORY: 0,
                    ResourceType.DISK: 0,
                    ResourceType.NETWORK: 0,
                    ResourceType.PROCESS: 0,
                    ResourceType.SYSTEM: 0
                }
            }
            
            # Initialize resource collectors
            self.resource_collectors = {
                ResourceType.CPU: self._collect_cpu_stats,
                ResourceType.MEMORY: self._collect_memory_stats,
                ResourceType.DISK: self._collect_disk_stats,
                ResourceType.NETWORK: self._collect_network_stats,
                ResourceType.PROCESS: self._collect_process_stats,
                ResourceType.SYSTEM: self._collect_system_stats
            }
            
            # Validate configuration
            self._validate_config()
            
            # Initialize state
            self._initialize_state()
            
            self.logger.info(
                "System statistics collector initialized",
                enabled=self.enabled,
                interval=self.collection_interval
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize system statistics collector: {str(e)}"
            self.logger.error(error_msg)
            raise SystemStatsInitializationError(error_msg) from e
    
    def _validate_config(self) -> None:
        """Validate configuration settings."""
        try:
            if not isinstance(self.collection_interval, (int, float)) or self.collection_interval <= 0:
                raise SystemStatsValidationError("Invalid collection interval")
            
            if not isinstance(self.enabled, bool):
                raise SystemStatsValidationError("Invalid enabled flag")
            
        except SystemStatsValidationError:
            raise
        except Exception as e:
            raise SystemStatsValidationError(f"Configuration validation failed: {str(e)}") from e
    
    def _initialize_state(self) -> None:
        """Initialize system stats state."""
        try:
            with self.state_lock:
                if self._is_initialized:
                    raise SystemStatsStateError("System stats already initialized")
                
                self._is_initialized = True
                self._is_shutting_down = False
                
                # Initialize statistics
                with self.stats_lock:
                    self.stats = {
                        "collection_errors": 0,
                        "last_collection_time": 0,
                        "total_collections": 0,
                        "total_errors": 0,
                        "total_warnings": 0,
                        "collection_times": [],
                        "resource_errors": {
                            ResourceType.CPU: 0,
                            ResourceType.MEMORY: 0,
                            ResourceType.DISK: 0,
                            ResourceType.NETWORK: 0,
                            ResourceType.PROCESS: 0,
                            ResourceType.SYSTEM: 0
                        }
                    }
                
        except Exception as e:
            raise SystemStatsStateError(f"State initialization failed: {str(e)}") from e
    
    def _handle_error(self, error: Exception, context: str) -> None:
        """Centralized error handling with logging and statistics."""
        try:
            error_type = type(error).__name__
            error_msg = str(error)
            
            # Update error statistics
            with self.stats_lock:
                self.stats["total_errors"] += 1
                self.stats["collection_errors"] += 1
                
                if isinstance(error, SystemStatsResourceError):
                    resource_type = getattr(error, 'resource_type', None)
                    if resource_type in self.stats["resource_errors"]:
                        self.stats["resource_errors"][resource_type] += 1
            
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
    
    def start(self) -> bool:
        """
        Start collecting system statistics.
        
        Returns:
            True if started successfully, False otherwise
            
        Raises:
            SystemStatsStateError: If starting fails
        """
        if not self.enabled:
            self.logger.info("System statistics collection is disabled")
            return False
        
        try:
            with self.state_lock:
                if self.running:
                    self.logger.warning("System statistics collector already running")
                    return False
                
                self.running = True
                self.collection_thread = threading.Thread(
                    target=self._collection_loop,
                    daemon=True,
                    name="SystemStatsCollector"
                )
                self.collection_thread.start()
                
                self.logger.info("System statistics collector started")
                return True
            
        except Exception as e:
            self.running = False
            raise SystemStatsStateError(f"Failed to start system statistics collector: {str(e)}") from e
    
    def stop(self) -> None:
        """
        Stop collecting system statistics.
        
        Raises:
            SystemStatsCleanupError: If stopping fails
        """
        try:
            with self.state_lock:
                if not self.running:
                    return
                
                self.running = False
                
                if self.collection_thread:
                    self.collection_thread.join(timeout=5)
                    if self.collection_thread.is_alive():
                        self.logger.warning("System statistics collector thread did not stop gracefully")
                
                # Log final statistics
                stats = self.get_statistics()
                self.logger.info(
                    "System statistics collector stopped",
                    extra={
                        'final_stats': stats,
                        'timestamp': datetime.now().isoformat()
                    }
                )
            
        except Exception as e:
            raise SystemStatsCleanupError(f"Failed to stop system statistics collector: {str(e)}") from e
    
    def get_current_stats(self) -> Optional[SystemStats]:
        """
        Get current system statistics.
        
        Returns:
            Current system statistics if available, None otherwise
            
        Raises:
            SystemStatsStateError: If retrieval fails
        """
        try:
            with self.stats_lock:
                return self.current_stats
        except Exception as e:
            raise SystemStatsStateError(f"Failed to get current statistics: {str(e)}") from e
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get collector statistics.
        
        Returns:
            Dictionary of collector statistics
            
        Raises:
            SystemStatsStateError: If retrieval fails
        """
        try:
            with self.stats_lock:
                return {
                    'collection_errors': self.stats['collection_errors'],
                    'last_collection_time': self.stats['last_collection_time'],
                    'total_collections': self.stats['total_collections'],
                    'total_errors': self.stats['total_errors'],
                    'total_warnings': self.stats['total_warnings'],
                    'collection_times': self.stats['collection_times'],
                    'resource_errors': self.stats['resource_errors']
                }
        except Exception as e:
            raise SystemStatsStateError(f"Failed to get statistics: {str(e)}") from e
    
    def _collection_loop(self) -> None:
        """Main collection loop."""
        while self.running:
            try:
                start_time = time.time()
                
                # Collect statistics
                stats = self._collect_stats()
                
                # Update current statistics
                with self.stats_lock:
                    self.current_stats = stats
                    self.stats["last_collection_time"] = start_time
                    self.stats["total_collections"] += 1
                    self.stats["collection_times"].append(time.time() - start_time)
                    
                    # Keep only the last 100 collection times
                    if len(self.stats["collection_times"]) > 100:
                        self.stats["collection_times"] = self.stats["collection_times"][-100:]
                
                # Sleep until next collection
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self._handle_error(e, "statistics collection")
                time.sleep(1)  # Sleep briefly before retrying
    
    def _collect_stats(self) -> SystemStats:
        """
        Collect system statistics.
        
        Returns:
            SystemStats object with current statistics
            
        Raises:
            SystemStatsResourceError: If statistics collection fails
        """
        start_time = time.time()
        warnings = []
        error_count = 0
        
        try:
            # Collect CPU statistics
            cpu_stats = self._collect_cpu_stats()
            if cpu_stats.error:
                warnings.append(f"CPU stats: {cpu_stats.error}")
                error_count += 1
            
            # Collect memory statistics
            memory_stats = self._collect_memory_stats()
            if memory_stats.error:
                warnings.append(f"Memory stats: {memory_stats.error}")
                error_count += 1
            
            # Collect disk statistics
            disk_stats = self._collect_disk_stats()
            if disk_stats.error:
                warnings.append(f"Disk stats: {disk_stats.error}")
                error_count += 1
            
            # Collect network statistics
            network_stats = self._collect_network_stats()
            if network_stats.error:
                warnings.append(f"Network stats: {network_stats.error}")
                error_count += 1
            
            # Collect process statistics
            process_stats = self._collect_process_stats()
            if process_stats.error:
                warnings.append(f"Process stats: {process_stats.error}")
                error_count += 1
            
            # Collect system statistics
            system_stats = self._collect_system_stats()
            if system_stats.error:
                warnings.append(f"System stats: {system_stats.error}")
                error_count += 1
            
            # Create SystemStats object
            stats = SystemStats(
                # CPU statistics
                cpu_percent=cpu_stats.values.get('percent', 0.0),
                cpu_count=cpu_stats.values.get('count', 0),
                cpu_freq=cpu_stats.values.get('freq', {}),
                cpu_load=cpu_stats.values.get('load', []),
                cpu_times=cpu_stats.values.get('times', {}),
                
                # Memory statistics
                memory_total=memory_stats.values.get('total', 0),
                memory_available=memory_stats.values.get('available', 0),
                memory_used=memory_stats.values.get('used', 0),
                memory_percent=memory_stats.values.get('percent', 0.0),
                swap_total=memory_stats.values.get('swap_total', 0),
                swap_used=memory_stats.values.get('swap_used', 0),
                swap_percent=memory_stats.values.get('swap_percent', 0.0),
                
                # Disk statistics
                disk_usage=disk_stats.values.get('usage', {}),
                disk_io=disk_stats.values.get('io', {}),
                
                # Network statistics
                network_io=network_stats.values.get('io', {}),
                network_connections=network_stats.values.get('connections', 0),
                network_addresses=network_stats.values.get('addresses', {}),
                
                # Process statistics
                process_count=process_stats.values.get('count', 0),
                thread_count=process_stats.values.get('thread_count', 0),
                handle_count=process_stats.values.get('handle_count', 0),
                process_memory=process_stats.values.get('memory', {}),
                
                # System information
                boot_time=system_stats.values.get('boot_time', 0.0),
                uptime=system_stats.values.get('uptime', 0.0),
                hostname=system_stats.values.get('hostname', ''),
                platform=system_stats.values.get('platform', ''),
                python_version=system_stats.values.get('python_version', ''),
                system_load=system_stats.values.get('load', []),
                
                # Performance metrics
                collection_time=time.time() - start_time,
                error_count=error_count,
                warnings=warnings
            )
            
            return stats
            
        except Exception as e:
            raise SystemStatsResourceError(f"Failed to collect system statistics: {str(e)}") from e
    
    def _collect_cpu_stats(self) -> ResourceStats:
        """Collect CPU statistics."""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            cpu_times = psutil.cpu_times()
            cpu_load = psutil.getloadavg()
            
            return ResourceStats(
                type=ResourceType.CPU,
                timestamp=time.time(),
                values={
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'freq': {
                        'current': cpu_freq.current,
                        'min': cpu_freq.min,
                        'max': cpu_freq.max
                    },
                    'times': {
                        'user': cpu_times.user,
                        'system': cpu_times.system,
                        'idle': cpu_times.idle,
                        'iowait': getattr(cpu_times, 'iowait', 0),
                        'irq': getattr(cpu_times, 'irq', 0),
                        'softirq': getattr(cpu_times, 'softirq', 0)
                    },
                    'load': list(cpu_load)
                }
            )
        except Exception as e:
            return ResourceStats(
                type=ResourceType.CPU,
                timestamp=time.time(),
                values={},
                error=str(e)
            )
    
    def _collect_memory_stats(self) -> ResourceStats:
        """Collect memory statistics."""
        try:
            # Get memory usage
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return ResourceStats(
                type=ResourceType.MEMORY,
                timestamp=time.time(),
                values={
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'percent': memory.percent,
                    'swap_total': swap.total,
                    'swap_used': swap.used,
                    'swap_percent': swap.percent
                }
            )
        except Exception as e:
            return ResourceStats(
                type=ResourceType.MEMORY,
                timestamp=time.time(),
                values={},
                error=str(e)
            )
    
    def _collect_disk_stats(self) -> ResourceStats:
        """Collect disk statistics."""
        try:
            # Get disk usage and I/O
            disk_usage = {}
            disk_io = {}
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                except Exception:
                    continue
            
            for disk, stats in psutil.disk_io_counters(perdisk=True).items():
                disk_io[disk] = {
                    'read_count': stats.read_count,
                    'write_count': stats.write_count,
                    'read_bytes': stats.read_bytes,
                    'write_bytes': stats.write_bytes,
                    'read_time': stats.read_time,
                    'write_time': stats.write_time
                }
            
            return ResourceStats(
                type=ResourceType.DISK,
                timestamp=time.time(),
                values={
                    'usage': disk_usage,
                    'io': disk_io
                }
            )
        except Exception as e:
            return ResourceStats(
                type=ResourceType.DISK,
                timestamp=time.time(),
                values={},
                error=str(e)
            )
    
    def _collect_network_stats(self) -> ResourceStats:
        """Collect network statistics."""
        try:
            # Get network I/O and connections
            network_io = {}
            network_addresses = {}
            
            for interface, stats in psutil.net_io_counters(pernic=True).items():
                network_io[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
            
            for interface, addrs in psutil.net_if_addrs().items():
                network_addresses[interface] = [
                    {
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    for addr in addrs
                ]
            
            return ResourceStats(
                type=ResourceType.NETWORK,
                timestamp=time.time(),
                values={
                    'io': network_io,
                    'connections': len(psutil.net_connections()),
                    'addresses': network_addresses
                }
            )
        except Exception as e:
            return ResourceStats(
                type=ResourceType.NETWORK,
                timestamp=time.time(),
                values={},
                error=str(e)
            )
    
    def _collect_process_stats(self) -> ResourceStats:
        """Collect process statistics."""
        try:
            # Get process information
            process_count = len(psutil.pids())
            thread_count = 0
            handle_count = 0
            process_memory = {
                'rss': 0,
                'vms': 0,
                'shared': 0,
                'text': 0,
                'lib': 0,
                'data': 0,
                'dirty': 0
            }
            
            for pid in psutil.pids():
                try:
                    process = psutil.Process(pid)
                    thread_count += process.num_threads()
                    
                    # Get handle count if available
                    if hasattr(process, 'num_handles'):
                        handle_count += process.num_handles()
                    
                    # Get memory info
                    memory_info = process.memory_info()
                    process_memory['rss'] += memory_info.rss
                    process_memory['vms'] += memory_info.vms
                    
                    # Get memory maps if available
                    if hasattr(process, 'memory_maps'):
                        for mmap in process.memory_maps():
                            process_memory['shared'] += mmap.shared_clean + mmap.shared_dirty
                            process_memory['text'] += mmap.text
                            process_memory['lib'] += mmap.lib
                            process_memory['data'] += mmap.data
                            process_memory['dirty'] += mmap.dirty
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return ResourceStats(
                type=ResourceType.PROCESS,
                timestamp=time.time(),
                values={
                    'count': process_count,
                    'thread_count': thread_count,
                    'handle_count': handle_count,
                    'memory': process_memory
                }
            )
        except Exception as e:
            return ResourceStats(
                type=ResourceType.PROCESS,
                timestamp=time.time(),
                values={},
                error=str(e)
            )
    
    def _collect_system_stats(self) -> ResourceStats:
        """Collect system statistics."""
        try:
            # Get system information
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            hostname = socket.gethostname()
            system_platform = platform.platform()
            python_version = sys.version
            
            # Get system load
            system_load = psutil.getloadavg()
            
            return ResourceStats(
                type=ResourceType.SYSTEM,
                timestamp=time.time(),
                values={
                    'boot_time': boot_time,
                    'uptime': uptime,
                    'hostname': hostname,
                    'platform': system_platform,
                    'python_version': python_version,
                    'load': list(system_load)
                }
            )
        except Exception as e:
            return ResourceStats(
                type=ResourceType.SYSTEM,
                timestamp=time.time(),
                values={},
                error=str(e)
            )

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
