"""
Main entry point for the Network Feature Extractor.
"""

import os
import sys
import time
import signal
import argparse
import threading
from typing import Dict, Any

# Import local modules
from .core.config import Config
from .core.packet_capture import PacketCapture
from .core.flow_tracker import FlowTracker
from .output.csv_writer import CSVWriter
from .monitoring.prometheus_exporter import PrometheusExporter
from .logging.logger import Logger


class NetworkFeatureExtractor:
    """Main application class for the Network Feature Extractor."""
    
    def __init__(self, config_path: str = None):
        """
        Initialize the application.
        
        Args:
            config_path: Path to configuration file
        """
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
        
        # Component health status
        self.component_health = {
            "packet_capture": True,
            "flow_tracker": True,
            "csv_writer": True,
            "prometheus_exporter": True
        }
        self.health_lock = threading.RLock()
    
    def initialize(self) -> None:
        """Initialize all components."""
        self.logger.info("Initializing Network Feature Extractor")
        
        try:
            # Initialize components
            self.logger.info("Initializing Prometheus exporter")
            self.prometheus_exporter = PrometheusExporter(self.config, self.logger_manager)
            
            self.logger.info("Initializing CSV writer")
            self.csv_writer = CSVWriter(self.config, self.logger_manager)
            
            self.logger.info("Initializing flow tracker")
            self.flow_tracker = FlowTracker(self.config, self.logger_manager)
            
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
            
            self.logger.info("Initialization complete")
        except Exception as e:
            self.logger.error("Failed to initialize: {}".format(str(e)))
            raise
    
    def start(self) -> None:
        """Start all components."""
        if self.running:
            self.logger.warning("Network Feature Extractor already running")
            return
        
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
            self.metrics_thread = threading.Thread(target=self._update_metrics)
            self.metrics_thread.daemon = True
            self.metrics_thread.start()
            
            # Start watchdog thread
            self.watchdog_thread = threading.Thread(target=self._watchdog_thread)
            self.watchdog_thread.daemon = True
            self.watchdog_thread.start()
            
            self.logger.info("Network Feature Extractor started")
            return True
        except Exception as e:
            self.logger.error("Failed to start Network Feature Extractor", error=str(e))
            self.stop()
            return False
    
    def stop(self) -> None:
        """Stop all components."""
        if not self.running:
            return
        
        self.logger.info("Stopping Network Feature Extractor")
        
        # Stop running flag
        self.running = False
        
        # Wait for metrics thread to stop
        if self.metrics_thread and self.metrics_thread.is_alive():
            self.metrics_thread.join(timeout=5.0)
        
        # Stop components in order
        if self.packet_capture:
            self.packet_capture.stop()
        
        if self.flow_tracker:
            self.flow_tracker.cleanup()
        
        if self.csv_writer:
            self.csv_writer.stop()
        
        if self.prometheus_exporter:
            self.prometheus_exporter.stop()
        
        self.logger.info("Network Feature Extractor stopped")
    
    def run(self) -> None:
        """Run the application until interrupted."""
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
            while self.running:
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
            self.logger.error("Unhandled exception", error=str(e))
        
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
        self.stop()
    
    def _update_metrics(self) -> None:
        """Update Prometheus metrics periodically."""
        update_interval = 5  # seconds
        
        while self.running:
            try:
                self.prometheus_exporter.update_metrics()
            except Exception as e:
                self.logger.error("Error updating metrics", error=str(e))
            
            time.sleep(update_interval)
    
    def _check_components_health(self) -> Dict[str, bool]:
        """
        Check the health of all components.
        
        Returns:
            Dictionary of component names to health status (True = healthy)
        """
        with self.health_lock:
            # Check packet capture health
            if self.packet_capture:
                self.component_health["packet_capture"] = self.packet_capture.is_running()
                
            # Check flow tracker health - for now just check if cleanup thread is alive
            if self.flow_tracker:
                self.component_health["flow_tracker"] = (
                    self.flow_tracker.cleanup_thread is not None and 
                    self.flow_tracker.cleanup_thread.is_alive()
                )
                
            # Check CSV writer health - for now just check if it's initialized
            if self.csv_writer:
                # We could add more sophisticated health checks here
                self.component_health["csv_writer"] = True
                
            # Check Prometheus exporter health
            if self.prometheus_exporter:
                self.component_health["prometheus_exporter"] = self.prometheus_exporter.is_running()
                
            return self.component_health.copy()
            
    def _watchdog_thread(self) -> None:
        """Thread function for monitoring component health and recovering when needed."""
        self.logger.info("Watchdog thread started")
        check_interval = 10  # Check health every 10 seconds
        
        while self.running:
            try:
                # Sleep first to give components time to initialize
                time.sleep(check_interval)
                
                # Check component health
                health = self._check_components_health()
                
                # Log overall health status
                unhealthy = [comp for comp, status in health.items() if not status]
                if unhealthy:
                    self.logger.warning(
                        "Unhealthy components detected", 
                        components=unhealthy
                    )
                    
                    # Attempt recovery for each unhealthy component
                    for component in unhealthy:
                        self._recover_component(component)
            
            except Exception as e:
                self.logger.error("Error in watchdog thread", error=str(e))
                # Don't sleep here - we want to retry quickly after an error
        
        self.logger.info("Watchdog thread stopped")
        
    def _recover_component(self, component: str) -> bool:
        """
        Attempt to recover an unhealthy component.
        
        Args:
            component: Component name to recover
            
        Returns:
            True if recovery was successful, False otherwise
        """
        self.logger.info(f"Attempting to recover {component}")
        
        if component == "packet_capture":
            # Restart packet capture
            if self.packet_capture:
                self.packet_capture.stop()
                time.sleep(1)  # Give it time to clean up
                
                # Attempt to restart
                capture_success = self.packet_capture.start(
                    self.flow_tracker.process_packet
                )
                
                if capture_success:
                    self.logger.info("Successfully recovered packet capture")
                    with self.health_lock:
                        self.component_health["packet_capture"] = True
                    return True
                else:
                    self.logger.error("Failed to recover packet capture")
        
        elif component == "flow_tracker":
            # Restart flow tracker
            if self.flow_tracker:
                # Save the callback
                callback = self.flow_tracker.complete_flow_callback
                
                # Stop the current flow tracker
                self.flow_tracker.cleanup()
                
                # Create a new flow tracker
                self.flow_tracker = FlowTracker(self.config, self.logger_manager)
                
                # Restore the callback
                if callback:
                    self.flow_tracker.register_flow_callback(callback)
                
                # Start the new flow tracker
                self.flow_tracker.start()
                
                self.logger.info("Successfully recovered flow tracker")
                with self.health_lock:
                    self.component_health["flow_tracker"] = True
                return True
        
        # Other components would have similar recovery logic
        
        return False


def main() -> None:
    """Main entry point."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Network Feature Extractor")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    args = parser.parse_args()
    
    # Run the application
    app = NetworkFeatureExtractor(args.config)
    app.run()


if __name__ == "__main__":
    main()
