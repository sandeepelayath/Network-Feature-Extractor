"""
Main entry point for the Network Feature Extractor.
"""

import os
import sys
import time
import signal
import argparse
import threading
import traceback
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime

# Import local modules
from .core.config import Config
from .core.packet_capture import PacketCapture
from .core.flow_tracker import FlowTracker
from .output.csv_writer import CSVWriter
from .monitoring.prometheus_exporter import PrometheusExporter
from .logging.logger import Logger
from .feature_extraction import FeatureExtractorRegistry


class ComponentStatus(Enum):
    """Enum for component health status."""
    HEALTHY = auto()
    DEGRADED = auto()
    FAILED = auto()
    UNKNOWN = auto()


@dataclass
class ComponentHealth:
    """Component health information."""
    status: ComponentStatus = ComponentStatus.UNKNOWN
    last_check: float = 0.0
    error_count: int = 0
    last_error: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    uptime: float = 0.0
    metrics: Dict[str, Any] = field(default_factory=dict)


class NetworkFeatureExtractor:
    """Main application class for the Network Feature Extractor."""
    
    def __init__(self, config_path: str = None):
        """
        Initialize the application.
        
        Args:
            config_path: Path to configuration file
            
        Raises:
            RuntimeError: If initialization fails
        """
        try:
            # Load configuration
            self.config = Config(config_path)
            
            # Initialize logger
            self.logger_manager = Logger(self.config)
            self.logger = self.logger_manager.get_logger()
            
            # Initialize components
            self.packet_capture = None
            self.flow_tracker = None
            self.csv_writer = None
            self.prometheus_exporter = None
            
            # Control flags
            self.running = False
            self.metrics_thread = None
            self.watchdog_thread = None
            self.shutdown_event = threading.Event()
            
            # Component health status
            self.component_health = {
                "packet_capture": ComponentHealth(),
                "flow_tracker": ComponentHealth(),
                "csv_writer": ComponentHealth(),
                "prometheus_exporter": ComponentHealth(),
                "feature_extractors": ComponentHealth()
            }
            self.health_lock = threading.RLock()
            
            # Performance metrics
            self.start_time = time.time()
            self.total_packets = 0
            self.total_flows = 0
            self.total_errors = 0
            self.metrics_lock = threading.RLock()
            
            self.logger.info("Network Feature Extractor initialized")
            
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Network Feature Extractor: {str(e)}")
    
    def initialize(self) -> None:
        """
        Initialize all components.
        
        Raises:
            RuntimeError: If initialization fails
        """
        self.logger.info("Initializing Network Feature Extractor")
        
        try:
            # Initialize components
            self.logger.info("Initializing Prometheus exporter")
            self.prometheus_exporter = PrometheusExporter(self.config, self.logger_manager)
            
            self.logger.info("Initializing CSV writer")
            self.csv_writer = CSVWriter(self.config, self.logger_manager)
            
            self.logger.info("Initializing flow tracker")
            self.flow_tracker = FlowTracker(self.config, self.logger_manager)
            
            # Log information about enabled feature extractors
            enabled_extractors = []
            if hasattr(self.flow_tracker, 'feature_extractor_registry'):
                registry = self.flow_tracker.feature_extractor_registry
                enabled_extractors = [
                    extractor.get_feature_name() 
                    for extractor in registry.get_enabled_extractors()
                ]
                
                self.logger.info(
                    "Feature extraction modules initialized", 
                    enabled_extractors=enabled_extractors,
                    feature_count=len(registry.get_all_feature_names())
                )
            
            self.logger.info("Initializing packet capture")
            interface = self.config.get('network', 'interface')
            mode = self.config.get('network', 'mode', 'xdp')
            sample_rate = self.config.get('network', 'sampling', {}).get('rate', 1.0)
            packet_queue_size = self.config.get('network', 'packet_queue_size', 100000)
            
            self.packet_capture = PacketCapture(
                interface=interface, 
                mode=mode, 
                sample_rate=sample_rate, 
                packet_queue_size=packet_queue_size
            )
            
            # Register callbacks
            self.flow_tracker.register_flow_callback(self.csv_writer.write_flow)
            
            # Register metric updaters
            self.prometheus_exporter.register_metric_updater(
                "packet_capture", self.packet_capture.get_statistics)
            self.prometheus_exporter.register_metric_updater(
                "flow_tracker", self.flow_tracker.get_statistics)
            
            # Register feature extractor metrics if available
            if hasattr(self.flow_tracker, 'feature_extractor_registry'):
                registry = self.flow_tracker.feature_extractor_registry
                for extractor in registry.get_enabled_extractors():
                    self.prometheus_exporter.register_metric_updater(
                        f"feature_{extractor.get_feature_name()}", 
                        extractor.get_statistics
                    )
            
            # Update health status
            with self.health_lock:
                for component in self.component_health:
                    self.component_health[component].status = ComponentStatus.HEALTHY
                    self.component_health[component].last_check = time.time()
            
            self.logger.info("Initialization complete")
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize",
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise RuntimeError(f"Failed to initialize: {str(e)}")
    
    def start(self) -> bool:
        """
        Start all components.
        
        Returns:
            True if started successfully, False otherwise
            
        Raises:
            RuntimeError: If starting fails
        """
        if self.running:
            self.logger.warning("Network Feature Extractor already running")
            return False
        
        self.logger.info("Starting Network Feature Extractor")
        
        try:
            # Start components in reverse order
            self.prometheus_exporter.start()
            self.csv_writer.start()
            self.flow_tracker.start()
            
            # Start packet capture last, with proper error handling
            capture_success = self.packet_capture.start(self.flow_tracker.process_packet)
            if not capture_success:
                raise RuntimeError("Failed to start packet capture")
            
            # Start metrics update thread
            self.running = True
            self.shutdown_event.clear()
            
            self.metrics_thread = threading.Thread(
                target=self._update_metrics,
                name="MetricsUpdater",
                daemon=True
            )
            self.metrics_thread.start()
            
            # Start watchdog thread
            self.watchdog_thread = threading.Thread(
                target=self._watchdog_thread,
                name="ComponentWatchdog",
                daemon=True
            )
            self.watchdog_thread.start()
            
            self.logger.info("Network Feature Extractor started")
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to start Network Feature Extractor",
                error=str(e),
                traceback=traceback.format_exc()
            )
            self.stop()
            return False
    
    def stop(self) -> None:
        """
        Stop all components.
        
        Raises:
            RuntimeError: If stopping fails
        """
        if not self.running:
            return
        
        self.logger.info("Stopping Network Feature Extractor")
        
        try:
            # Set shutdown event
            self.shutdown_event.set()
            
            # Stop running flag
            self.running = False
            
            # Wait for metrics thread to stop
            if self.metrics_thread and self.metrics_thread.is_alive():
                self.metrics_thread.join(timeout=5.0)
                if self.metrics_thread.is_alive():
                    self.logger.warning("Metrics thread did not stop gracefully")
            
            # Wait for watchdog thread to stop
            if self.watchdog_thread and self.watchdog_thread.is_alive():
                self.watchdog_thread.join(timeout=5.0)
                if self.watchdog_thread.is_alive():
                    self.logger.warning("Watchdog thread did not stop gracefully")
            
            # Stop components in order
            if self.packet_capture:
                self.packet_capture.stop()
            
            if self.flow_tracker:
                self.flow_tracker.cleanup()
            
            if self.csv_writer:
                self.csv_writer.stop()
            
            if self.prometheus_exporter:
                self.prometheus_exporter.stop()
            
            # Update health status
            with self.health_lock:
                for component in self.component_health:
                    self.component_health[component].status = ComponentStatus.UNKNOWN
                    self.component_health[component].uptime = time.time() - self.component_health[component].start_time
            
            self.logger.info("Network Feature Extractor stopped")
            
        except Exception as e:
            raise RuntimeError(f"Failed to stop Network Feature Extractor: {str(e)}")
    
    def run(self) -> None:
        """
        Run the application until interrupted.
        
        Raises:
            RuntimeError: If an unhandled exception occurs
        """
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            # Initialize and start
            self.initialize()
            start_success = self.start()
            
            if not start_success:
                self.logger.error("Failed to start application")
                return
            
            # Run until interrupted
            self.logger.info("Network Feature Extractor running, press Ctrl+C to stop")
            
            # Keep main thread alive
            while self.running and not self.shutdown_event.is_set():
                time.sleep(1)
                
                # Check if packet capture is still running
                if not self.packet_capture or not self.packet_capture.is_running():
                    self.logger.error("Packet capture stopped unexpectedly, restarting...")
                    self.stop()
                    
                    # Wait a moment before restarting
                    time.sleep(5)
                    
                    # Attempt to restart
                    self.initialize()
                    if not self.start():
                        self.logger.error("Failed to restart, exiting")
                        break
        
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received, stopping")
        
        except Exception as e:
            self.logger.error(
                "Unhandled exception",
                error=str(e),
                traceback=traceback.format_exc()
            )
            raise RuntimeError(f"Unhandled exception: {str(e)}")
        
        finally:
            self.stop()
    
    def _signal_handler(self, sig, frame) -> None:
        """
        Handle signals.
        
        Args:
            sig: Signal number
            frame: Frame object
        """
        self.logger.info("Signal received, stopping", signal=sig)
        self.shutdown_event.set()
    
    def _update_metrics(self) -> None:
        """Update Prometheus metrics periodically."""
        while self.running and not self.shutdown_event.is_set():
            try:
                # Update component health
                health_status = self._check_components_health()
                
                # Update metrics
                with self.metrics_lock:
                    self.total_packets = self.packet_capture.get_statistics().get('total_packets', 0)
                    self.total_flows = self.flow_tracker.get_statistics().get('total_flows', 0)
                
                # Sleep for update interval
                time.sleep(self.config.get('monitoring', 'metrics_interval', 10))
                
            except Exception as e:
                self.logger.error(
                    "Error updating metrics",
                    error=str(e),
                    traceback=traceback.format_exc()
                )
                with self.metrics_lock:
                    self.total_errors += 1
                time.sleep(1)  # Sleep briefly before retrying
    
    def _check_components_health(self) -> Dict[str, bool]:
        """
        Check health of all components.
        
        Returns:
            Dictionary of component health status
        """
        health_status = {}
        
        try:
            with self.health_lock:
                # Check packet capture
                if self.packet_capture and self.packet_capture.is_running():
                    self.component_health["packet_capture"].status = ComponentStatus.HEALTHY
                else:
                    self.component_health["packet_capture"].status = ComponentStatus.FAILED
                
                # Check flow tracker
                if self.flow_tracker and self.flow_tracker.is_running():
                    self.component_health["flow_tracker"].status = ComponentStatus.HEALTHY
                else:
                    self.component_health["flow_tracker"].status = ComponentStatus.FAILED
                
                # Check CSV writer
                if self.csv_writer and self.csv_writer.is_running():
                    self.component_health["csv_writer"].status = ComponentStatus.HEALTHY
                else:
                    self.component_health["csv_writer"].status = ComponentStatus.FAILED
                
                # Check Prometheus exporter
                if self.prometheus_exporter and self.prometheus_exporter.is_running():
                    self.component_health["prometheus_exporter"].status = ComponentStatus.HEALTHY
                else:
                    self.component_health["prometheus_exporter"].status = ComponentStatus.FAILED
                
                # Update last check time
                for component in self.component_health:
                    self.component_health[component].last_check = time.time()
                    health_status[component] = self.component_health[component].status == ComponentStatus.HEALTHY
            
            return health_status
            
        except Exception as e:
            self.logger.error(
                "Error checking component health",
                error=str(e),
                traceback=traceback.format_exc()
            )
            return {component: False for component in self.component_health}
    
    def _watchdog_thread(self) -> None:
        """Monitor component health and restart failed components."""
        while self.running and not self.shutdown_event.is_set():
            try:
                # Check component health
                health_status = self._check_components_health()
                
                # Restart failed components
                for component, is_healthy in health_status.items():
                    if not is_healthy:
                        self.logger.warning(f"Component {component} is not healthy, attempting restart")
                        self._restart_component(component)
                
                # Sleep for check interval
                time.sleep(self.config.get('monitoring', 'health_check_interval', 30))
                
            except Exception as e:
                self.logger.error(
                    "Error in watchdog thread",
                    error=str(e),
                    traceback=traceback.format_exc()
                )
                time.sleep(1)  # Sleep briefly before retrying
    
    def _restart_component(self, component: str) -> None:
        """
        Restart a failed component.
        
        Args:
            component: Name of the component to restart
            
        Raises:
            ValueError: If component name is invalid
        """
        try:
            if component == "packet_capture":
                if self.packet_capture:
                    self.packet_capture.stop()
                    self.packet_capture.start(self.flow_tracker.process_packet)
            elif component == "flow_tracker":
                if self.flow_tracker:
                    self.flow_tracker.cleanup()
                    self.flow_tracker.start()
            elif component == "csv_writer":
                if self.csv_writer:
                    self.csv_writer.stop()
                    self.csv_writer.start()
            elif component == "prometheus_exporter":
                if self.prometheus_exporter:
                    self.prometheus_exporter.stop()
                    self.prometheus_exporter.start()
            else:
                raise ValueError(f"Invalid component name: {component}")
            
            # Update health status
            with self.health_lock:
                self.component_health[component].status = ComponentStatus.HEALTHY
                self.component_health[component].error_count = 0
                self.component_health[component].last_error = None
            
            self.logger.info(f"Component {component} restarted successfully")
            
        except Exception as e:
            self.logger.error(
                f"Failed to restart component {component}",
                error=str(e),
                traceback=traceback.format_exc()
            )
            with self.health_lock:
                self.component_health[component].status = ComponentStatus.FAILED
                self.component_health[component].error_count += 1
                self.component_health[component].last_error = str(e)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Network Feature Extractor")
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file",
        default=None
    )
    args = parser.parse_args()
    
    try:
        extractor = NetworkFeatureExtractor(args.config)
        extractor.run()
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
