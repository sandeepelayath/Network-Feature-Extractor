"""
Prometheus metrics exporter for the Network Feature Extractor.
"""

import threading
import time
from typing import Dict, Any, Callable, Optional
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import psutil
from prometheus_client.exposition import ThreadingWSGIServer
from datetime import datetime

# Import local modules
from ..core.config import Config
from ..logging.logger import Logger

class PrometheusError(Exception):
    """Base exception for Prometheus exporter errors."""
    pass

class PrometheusInitializationError(PrometheusError):
    """Exception raised during Prometheus exporter initialization."""
    pass

class PrometheusCleanupError(PrometheusError):
    """Exception raised during Prometheus exporter cleanup."""
    pass

class PrometheusMetricsError(PrometheusError):
    """Exception raised during metrics operations."""
    pass

class PrometheusConfigError(PrometheusError):
    """Exception raised during configuration validation."""
    pass

class PrometheusStateError(PrometheusError):
    """Exception raised during state management."""
    pass

class PrometheusIOError(PrometheusError):
    """Exception raised during I/O operations."""
    pass

class PrometheusResourceError(PrometheusError):
    """Exception raised when resource limits are exceeded."""
    pass

class PrometheusTimeoutError(PrometheusError):
    """Exception raised when operations timeout."""
    pass

class PrometheusExporter:
    """Prometheus metrics exporter for the Network Feature Extractor."""
    
    def __init__(self, config: Config, logger: Logger):
        """
        Initialize the Prometheus exporter.
        
        Args:
            config: Configuration object
            logger: Logger instance
            
        Raises:
            PrometheusInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger.get_logger("monitoring")
            
            # Validate configuration
            self._validate_config()
            
            # Prometheus configuration
            self.enabled = self.config.get('monitoring', 'prometheus', {}).get('enabled', True)
            self.port = self.config.get('monitoring', 'prometheus', {}).get('port', 5000)
            
            # System stats configuration
            self.system_stats_enabled = self.config.get('monitoring', 'system_stats', {}).get('enabled', True)
            self.system_stats_interval = self.config.get('monitoring', 'system_stats', {}).get('interval', 10)
            
            # Server and thread
            self.server_started = False
            self.running = False
            self.update_thread = None
            self.server = None
            self.state_lock = threading.RLock()
            self._is_initialized = False
            self._is_shutting_down = False
            
            # Initialize metrics
            self._init_metrics()
            
            # Register metric updater callbacks
            self.metric_updaters = {}
            self.metric_updaters_lock = threading.RLock()
            
            # Initialize statistics
            self.stats = {
                "startup_errors": 0,
                "fatal_errors": 0,
                "processing_errors": 0,
                "metric_errors": 0,
                "resource_errors": 0,
                "timeout_errors": 0,
                "io_errors": 0,
                "total_errors": 0,
                "last_error_time": 0,
                "error_history": []
            }
            
            # Initialize state
            self._initialize_state()
            
            self.logger.info(
                "Prometheus exporter initialized",
                enabled=self.enabled,
                port=self.port
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize Prometheus exporter: {str(e)}"
            self.logger.error(error_msg)
            raise PrometheusInitializationError(error_msg) from e
    
    def _validate_config(self) -> None:
        """Validate Prometheus exporter configuration."""
        try:
            # Validate port
            if not 1024 <= self.config.get('monitoring', 'prometheus', {}).get('port', 5000) <= 65535:
                raise PrometheusConfigError("Port must be between 1024 and 65535")
            
            # Validate system stats interval
            if self.config.get('monitoring', 'system_stats', {}).get('interval', 10) <= 0:
                raise PrometheusConfigError("System stats interval must be positive")
            
        except Exception as e:
            raise PrometheusConfigError(f"Configuration validation failed: {str(e)}") from e
    
    def _initialize_state(self) -> None:
        """Initialize exporter state."""
        try:
            with self.state_lock:
                if self._is_initialized:
                    raise PrometheusStateError("Exporter already initialized")
                
                self._is_initialized = True
                self._is_shutting_down = False
                self.server_started = False
                self.running = False
                
                # Initialize statistics
                self.stats = {
                    "startup_errors": 0,
                    "fatal_errors": 0,
                    "processing_errors": 0,
                    "metric_errors": 0,
                    "resource_errors": 0,
                    "timeout_errors": 0,
                    "io_errors": 0,
                    "total_errors": 0,
                    "last_error_time": 0,
                    "error_history": []
                }
                
        except Exception as e:
            raise PrometheusStateError(f"State initialization failed: {str(e)}") from e
    
    def _validate_state(self) -> None:
        """Validate current state of the exporter."""
        try:
            with self.state_lock:
                if self.running and not self.server_started:
                    raise PrometheusStateError("Running state but server not started")
                if self.server_started and not self.server:
                    raise PrometheusStateError("Server started but no server instance")
                if self.system_stats_enabled and self.running and not self.update_thread:
                    raise PrometheusStateError("System stats enabled but no update thread")
                if self._is_shutting_down and self.running:
                    raise PrometheusStateError("Shutting down but still running")
        except Exception as e:
            raise PrometheusStateError(f"State validation failed: {str(e)}") from e
    
    def _update_state(self, new_state: bool) -> None:
        """Update exporter state with error handling."""
        try:
            with self.state_lock:
                old_state = self.running
                self.running = new_state
                
                if old_state != new_state:
                    self.logger.info(
                        "Exporter state changed",
                        old_state=old_state,
                        new_state=new_state
                    )
        except Exception as e:
            raise PrometheusStateError(f"Failed to update state: {str(e)}") from e
    
    def _cleanup_resources(self) -> None:
        """Cleanup resources with error handling."""
        try:
            # Stop server
            if self.server:
                try:
                    self.server.shutdown()
                    self.server = None
                except Exception as e:
                    self._handle_error(e, "server shutdown", "error", "fatal_errors")
            
            # Stop update thread
            if self.update_thread and self.update_thread.is_alive():
                try:
                    self.update_thread.join(timeout=5.0)
                    if self.update_thread.is_alive():
                        self.logger.warning("Update thread did not terminate cleanly")
                except Exception as e:
                    self._handle_error(e, "update thread cleanup", "error", "fatal_errors")
            
            # Clear metric updaters
            try:
                with self.metric_updaters_lock:
                    self.metric_updaters.clear()
            except Exception as e:
                self._handle_error(e, "metric updaters cleanup", "error", "fatal_errors")
            
        except Exception as e:
            raise PrometheusCleanupError(f"Resource cleanup failed: {str(e)}") from e
    
    def _init_metrics(self) -> None:
        """Initialize Prometheus metrics with error handling."""
        try:
            # Packet metrics
            self.packet_counter = Counter(
                'netflow_packets_total', 
                'Total number of packets processed',
                ['direction']
            )
            
            self.dropped_packet_counter = Counter(
                'netflow_dropped_packets_total',
                'Total number of packets dropped'
            )
            
            self.sampled_packet_counter = Counter(
                'netflow_sampled_packets_total',
                'Total number of packets included in sampling'
            )
            
            # Protocol metrics
            self.protocol_counter = Counter(
                'netflow_packets_protocol_total',
                'Total number of packets by protocol',
                ['protocol']
            )
            
            self.ipv4_packets = Counter(
                'netflow_ipv4_packets_total',
                'Total number of IPv4 packets'
            )
            
            self.ipv6_packets = Counter(
                'netflow_ipv6_packets_total',
                'Total number of IPv6 packets'
            )
            
            # Flow metrics
            self.flow_counter = Counter(
                'netflow_flows_total',
                'Total number of flows',
                ['status']
            )
            
            self.active_flows_gauge = Gauge(
                'netflow_active_flows',
                'Number of currently active flows'
            )
            
            self.flow_duration_histogram = Histogram(
                'netflow_flow_duration_seconds',
                'Flow duration in seconds',
                buckets=(1, 5, 10, 30, 60, 300, 600, 1800, 3600)
            )
            
            # System metrics
            self.cpu_gauge = Gauge(
                'system_cpu_usage_percent',
                'CPU usage percentage'
            )
            
            self.memory_gauge = Gauge(
                'system_memory_usage_percent',
                'Memory usage percentage'
            )
            
            self.disk_io_counter = Counter(
                'system_disk_io_bytes_total',
                'Total disk I/O in bytes',
                ['direction']
            )
            
            self.network_io_counter = Counter(
                'system_network_io_bytes_total',
                'Total network I/O in bytes',
                ['direction']
            )
            
            # Initialize last update time and counters
            self.last_update_time = time.time()
            self.last_disk_read = 0
            self.last_disk_write = 0
            self.last_net_sent = 0
            self.last_net_recv = 0
            
        except Exception as e:
            raise PrometheusInitializationError(f"Failed to initialize metrics: {str(e)}") from e
    
    def start(self) -> None:
        """
        Start the Prometheus exporter server with error handling.
        
        Raises:
            PrometheusError: If start operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.enabled:
                self.logger.info("Prometheus exporter disabled")
                return
            
            if self.server_started:
                self.logger.warning("Prometheus exporter already started")
                return
            
            # Start HTTP server
            try:
                self.server = ThreadingWSGIServer(('', self.port), start_http_server)
                self.server_started = True
                self._update_state(True)
            except Exception as e:
                raise PrometheusIOError(f"Failed to start HTTP server: {str(e)}") from e
            
            # Start update thread for system stats
            if self.system_stats_enabled:
                try:
                    self.update_thread = threading.Thread(target=self._update_system_stats)
                    self.update_thread.daemon = True
                    self.update_thread.start()
                except Exception as e:
                    raise PrometheusError(f"Failed to start update thread: {str(e)}") from e
            
            self.logger.info("Prometheus exporter started", port=self.port)
            
        except Exception as e:
            self._handle_error(e, "start", "error", "startup_errors")
            raise PrometheusError(f"Failed to start exporter: {str(e)}") from e
    
    def stop(self) -> None:
        """
        Stop the Prometheus exporter with error handling.
        
        Raises:
            PrometheusError: If stop operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                self.logger.warning("Prometheus exporter already stopped")
                return
            
            # Update state first
            self._update_state(False)
            
            # Cleanup resources
            self._cleanup_resources()
            
            self.logger.info("Prometheus exporter stopped")
            
        except Exception as e:
            self._handle_error(e, "stop", "error", "fatal_errors")
            raise PrometheusError(f"Failed to stop exporter: {str(e)}") from e
    
    def register_metric_updater(self, name: str, callback: Callable[[], Dict[str, Any]]) -> None:
        """
        Register a callback function to update metrics with error handling.
        
        Args:
            name: Name of the metric updater
            callback: Function that returns a dictionary of metrics
            
        Raises:
            PrometheusMetricsError: If registration fails
        """
        try:
            with self.metric_updaters_lock:
                self.metric_updaters[name] = callback
                self.logger.info("Registered metric updater", name=name)
        except Exception as e:
            raise PrometheusMetricsError(f"Failed to register metric updater: {str(e)}") from e
    
    def update_metrics(self) -> None:
        """
        Update metrics from registered callbacks with error handling.
        
        Raises:
            PrometheusMetricsError: If update fails
        """
        try:
            with self.metric_updaters_lock:
                for name, callback in self.metric_updaters.items():
                    try:
                        metrics = callback()
                        self._process_metrics(name, metrics)
                    except Exception as e:
                        self._handle_error(e, f"metric update for {name}", "error", "metric_errors")
        except Exception as e:
            raise PrometheusMetricsError(f"Failed to update metrics: {str(e)}") from e
    
    def _process_metrics(self, source: str, metrics: Dict[str, Any]) -> None:
        """
        Process metrics from a callback with error handling.
        
        Args:
            source: Name of the metric source
            metrics: Dictionary of metrics
            
        Raises:
            PrometheusMetricsError: If processing fails
        """
        try:
            if source == "packet_capture":
                # Update packet metrics
                if "processed_packets" in metrics:
                    self.packet_counter.labels(direction="total").inc(metrics.get("processed_packets", 0))
                if "dropped_packets" in metrics:
                    self.dropped_packet_counter.inc(metrics.get("dropped_packets", 0))
                if "sampled_packets" in metrics:
                    self.sampled_packet_counter.inc(metrics.get("sampled_packets", 0))
                if "ipv4_packets" in metrics:
                    self.ipv4_packets.inc(metrics.get("ipv4_packets", 0))
                if "ipv6_packets" in metrics:
                    self.ipv6_packets.inc(metrics.get("ipv6_packets", 0))
            
            elif source == "flow_tracker":
                # Update flow metrics
                if "active_flows" in metrics:
                    self.active_flows_gauge.set(metrics.get("active_flows", 0))
                if "completed_flows" in metrics:
                    self.flow_counter.labels(status="completed").inc(metrics.get("completed_flows", 0))
                if "expired_flows" in metrics:
                    self.flow_counter.labels(status="expired").inc(metrics.get("expired_flows", 0))
            
            elif source == "flow_metrics":
                # Update flow duration histogram
                if "flow_duration" in metrics:
                    self.flow_duration_histogram.observe(metrics.get("flow_duration", 0))
                
                # Update protocol counter
                if "protocol" in metrics:
                    protocol_name = self._protocol_num_to_name(metrics.get("protocol", 0))
                    self.protocol_counter.labels(protocol=protocol_name).inc()
                
                # Update direction-specific packet counters
                if "total_fwd_packets" in metrics:
                    self.packet_counter.labels(direction="forward").inc(metrics.get("total_fwd_packets", 0))
                if "total_bwd_packets" in metrics:
                    self.packet_counter.labels(direction="backward").inc(metrics.get("total_bwd_packets", 0))
            
        except Exception as e:
            raise PrometheusMetricsError(f"Failed to process metrics: {str(e)}") from e
    
    def _update_system_stats(self) -> None:
        """Update system statistics metrics periodically with error handling."""
        while self.running:
            try:
                # CPU usage
                try:
                    cpu_percent = psutil.cpu_percent(interval=None)
                    self.cpu_gauge.set(cpu_percent)
                except Exception as e:
                    self._handle_error(e, "CPU metrics update", "error", "metric_errors")
                
                # Memory usage
                try:
                    memory = psutil.virtual_memory()
                    self.memory_gauge.set(memory.percent)
                except Exception as e:
                    self._handle_error(e, "memory metrics update", "error", "metric_errors")
                
                # Disk I/O
                try:
                    disk_io = psutil.disk_io_counters()
                    if disk_io:
                        current_time = time.time()
                        time_diff = current_time - self.last_update_time
                        
                        if time_diff > 0:
                            read_rate = (disk_io.read_bytes - self.last_disk_read) / time_diff
                            write_rate = (disk_io.write_bytes - self.last_disk_write) / time_diff
                            
                            self.disk_io_counter.labels(direction="read").inc(read_rate)
                            self.disk_io_counter.labels(direction="write").inc(write_rate)
                            
                            self.last_disk_read = disk_io.read_bytes
                            self.last_disk_write = disk_io.write_bytes
                except Exception as e:
                    self._handle_error(e, "disk I/O metrics update", "error", "metric_errors")
                
                # Network I/O
                try:
                    net_io = psutil.net_io_counters()
                    if net_io:
                        current_time = time.time()
                        time_diff = current_time - self.last_update_time
                        
                        if time_diff > 0:
                            sent_rate = (net_io.bytes_sent - self.last_net_sent) / time_diff
                            recv_rate = (net_io.bytes_recv - self.last_net_recv) / time_diff
                            
                            self.network_io_counter.labels(direction="sent").inc(sent_rate)
                            self.network_io_counter.labels(direction="received").inc(recv_rate)
                            
                            self.last_net_sent = net_io.bytes_sent
                            self.last_net_recv = net_io.bytes_recv
                except Exception as e:
                    self._handle_error(e, "network I/O metrics update", "error", "metric_errors")
                
                self.last_update_time = time.time()
                time.sleep(self.system_stats_interval)
                
            except Exception as e:
                self._handle_error(e, "system stats update", "error", "processing_errors")
                time.sleep(self.system_stats_interval)
    
    def _handle_error(self, error: Exception, context: str,
                     severity: str = "error", stat_key: str = "processing_errors") -> None:
        """
        Handle errors with error handling.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            severity: Error severity ('error' or 'warning')
            stat_key: Statistics key to update
            
        Raises:
            PrometheusError: If error handling fails
        """
        try:
            # Update error statistics
            self.stats[stat_key] += 1
            self.stats["total_errors"] += 1
            self.stats["last_error_time"] = time.time()
            
            # Add to error history
            self.stats["error_history"].append({
                "time": time.time(),
                "context": context,
                "error": str(error),
                "type": type(error).__name__
            })
            
            # Keep only the last 100 errors
            if len(self.stats["error_history"]) > 100:
                self.stats["error_history"] = self.stats["error_history"][-100:]
            
            # Log error
            log_method = getattr(self.logger, severity)
            log_method(
                f"Error in {context}",
                error=str(error),
                error_type=type(error).__name__,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            raise PrometheusError(f"Error handling failed: {str(e)}") from e
    
    @staticmethod
    def _protocol_num_to_name(protocol: int) -> str:
        """
        Convert protocol number to name with error handling.
        
        Args:
            protocol: Protocol number
            
        Returns:
            Protocol name
            
        Raises:
            PrometheusMetricsError: If conversion fails
        """
        try:
            protocol_names = {
                1: "ICMP",
                6: "TCP",
                17: "UDP",
                47: "GRE",
                50: "ESP",
                51: "AH",
                58: "ICMPv6"
            }
            return protocol_names.get(protocol, f"Unknown({protocol})")
        except Exception as e:
            raise PrometheusMetricsError(f"Failed to convert protocol number to name: {str(e)}") from e

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
