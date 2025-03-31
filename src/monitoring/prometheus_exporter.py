"""
Prometheus metrics exporter for the Network Feature Extractor.
"""

import threading
import time
from typing import Dict, Any, Callable
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import psutil

# Import local modules
from ..core.config import Config


class PrometheusExporter:
    """Prometheus metrics exporter for the Network Feature Extractor."""
    
    def __init__(self, config: Config, logger):
        """
        Initialize the Prometheus exporter.
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger.get_logger("monitoring")
        
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
        
        # Initialize metrics
        self._init_metrics()
        
        # Register metric updater callbacks
        self.metric_updaters = {}
    
    def _init_metrics(self) -> None:
        """Initialize Prometheus metrics."""
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
            'Total number of flows processed',
            ['status']
        )
        
        self.active_flows_gauge = Gauge(
            'netflow_active_flows',
            'Current number of active flows'
        )
        
        # Timing metrics
        self.flow_duration_histogram = Histogram(
            'netflow_flow_duration_seconds',
            'Flow duration in seconds',
            buckets=(0.1, 1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600)
        )
        
        # System metrics
        if self.system_stats_enabled:
            self.cpu_gauge = Gauge(
                'netflow_cpu_percent',
                'CPU usage percentage'
            )
            
            self.memory_gauge = Gauge(
                'netflow_memory_percent',
                'Memory usage percentage'
            )
            
            self.disk_io_counter = Counter(
                'netflow_disk_io_bytes_total',
                'Total disk I/O bytes',
                ['direction']
            )
            
            self.network_io_counter = Counter(
                'netflow_network_io_bytes_total',
                'Total network I/O bytes',
                ['direction']
            )
            
            # Track last disk and network IO values for rate calculation
            self.last_disk_read = 0
            self.last_disk_write = 0
            self.last_net_sent = 0
            self.last_net_recv = 0
            self.last_update_time = time.time()
    
    def start(self) -> None:
        """Start the Prometheus exporter server."""
        if not self.enabled:
            self.logger.info("Prometheus exporter disabled")
            return
        
        if self.server_started:
            self.logger.warning("Prometheus exporter already started")
            return
        
        try:
            # Start HTTP server
            start_http_server(self.port)
            self.server_started = True
            self.running = True
            
            # Start update thread for system stats
            if self.system_stats_enabled:
                self.update_thread = threading.Thread(target=self._update_system_stats)
                self.update_thread.daemon = True
                self.update_thread.start()
            
            self.logger.info("Prometheus exporter started", port=self.port)
        except Exception as e:
            self.logger.error("Failed to start Prometheus exporter", error=str(e))
    
    def stop(self) -> None:
        """Stop the Prometheus exporter."""
        self.running = False
        
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=5.0)
        
        self.logger.info("Prometheus exporter stopped")
    
    def register_metric_updater(self, name: str, callback: Callable[[], Dict[str, Any]]) -> None:
        """
        Register a callback function to update metrics.
        
        Args:
            name: Name of the metric updater
            callback: Function that returns a dictionary of metrics
        """
        self.metric_updaters[name] = callback
        self.logger.info("Registered metric updater", name=name)
    
    def update_metrics(self) -> None:
        """Update metrics from registered callbacks."""
        for name, callback in self.metric_updaters.items():
            try:
                metrics = callback()
                self._process_metrics(name, metrics)
            except Exception as e:
                self.logger.error("Error updating metrics", name=name, error=str(e))
    
    def _process_metrics(self, source: str, metrics: Dict[str, Any]) -> None:
        """
        Process metrics from a callback.
        
        Args:
            source: Name of the metric source
            metrics: Dictionary of metrics
        """
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
    
    def _update_system_stats(self) -> None:
        """Update system statistics metrics periodically."""
        while self.running:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=None)
                self.cpu_gauge.set(cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                self.memory_gauge.set(memory.percent)
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    current_time = time.time()
                    time_diff = current_time - self.last_update_time
                    
                    # Calculate rates and update counters
                    read_diff = disk_io.read_bytes - self.last_disk_read
                    write_diff = disk_io.write_bytes - self.last_disk_write
                    
                    if read_diff > 0:
                        self.disk_io_counter.labels(direction="read").inc(read_diff)
                    if write_diff > 0:
                        self.disk_io_counter.labels(direction="write").inc(write_diff)
                    
                    # Update last values
                    self.last_disk_read = disk_io.read_bytes
                    self.last_disk_write = disk_io.write_bytes
                
                # Network I/O
                net_io = psutil.net_io_counters()
                if net_io:
                    # Calculate rates and update counters
                    sent_diff = net_io.bytes_sent - self.last_net_sent
                    recv_diff = net_io.bytes_recv - self.last_net_recv
                    
                    if sent_diff > 0:
                        self.network_io_counter.labels(direction="sent").inc(sent_diff)
                    if recv_diff > 0:
                        self.network_io_counter.labels(direction="recv").inc(recv_diff)
                    
                    # Update last values
                    self.last_net_sent = net_io.bytes_sent
                    self.last_net_recv = net_io.bytes_recv
                
                self.last_update_time = current_time
                
            except Exception as e:
                self.logger.error("Error updating system stats", error=str(e))
            
            # Sleep until next update
            time.sleep(self.system_stats_interval)
    
    @staticmethod
    def _protocol_num_to_name(protocol: int) -> str:
        """
        Convert protocol number to name.
        
        Args:
            protocol: Protocol number
            
        Returns:
            Protocol name
        """
        protocol_map = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            33: "dccp",
            46: "rsvp",
            58: "icmpv6",
            132: "sctp"
        }
        
        return protocol_map.get(protocol, "other")
