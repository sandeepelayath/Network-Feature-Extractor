"""
Basic Metrics feature extractor for the Network Feature Extractor.
Extracts basic metrics from network flows with enhanced error handling and performance monitoring.
"""

import math
from typing import Dict, Any, List
import threading
import time
from datetime import datetime

from .base import (
    BaseFeatureExtractor, FeatureError, FeatureInitializationError,
    FeatureCleanupError, FeatureStatsError, FeatureConfigError,
    FeatureStateError, FeatureDependencyError, FeatureIOError,
    FeatureResourceError, FeatureTimeoutError
)
from ..core.config import Config
from ..logging.logger import Logger


class BasicMetricsError(FeatureError):
    """Base exception for basic metrics errors."""
    pass


class BasicMetricsInitializationError(FeatureInitializationError):
    """Exception raised during basic metrics initialization."""
    pass


class BasicMetricsCleanupError(FeatureCleanupError):
    """Exception raised during basic metrics cleanup."""
    pass


class BasicMetricsStatsError(FeatureStatsError):
    """Exception raised during basic metrics statistics management."""
    pass


class BasicMetricsConfigError(FeatureConfigError):
    """Exception raised during basic metrics configuration validation."""
    pass


class BasicMetricsStateError(FeatureStateError):
    """Exception raised during basic metrics state management."""
    pass


class BasicMetricsIOError(FeatureIOError):
    """Exception raised during basic metrics I/O operations."""
    pass


class BasicMetricsResourceError(FeatureResourceError):
    """Exception raised when basic metrics resource limits are exceeded."""
    pass


class BasicMetricsTimeoutError(FeatureTimeoutError):
    """Exception raised when basic metrics operations timeout."""
    pass


class BasicMetricsExtractor(BaseFeatureExtractor):
    """
    Basic Metrics feature extractor.
    
    Extracts the following features:
    - Flow duration
    - Packet counts
    - Byte counts
    - Flow rate metrics
    - Transfer ratios
    """
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the basic metrics extractor.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            
        Raises:
            BasicMetricsInitializationError: If initialization fails
        """
        try:
            super().__init__(config, logger_manager, 'basic_metrics')
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.running = False
            self.initialized = False
            self._is_shutting_down = False
            
            # Default thresholds
            self.min_packets_for_valid_ratios = 10
            
            # Statistics
            self.stats_lock = threading.RLock()
            self.stats = {
                "flows_processed": 0,
                "features_extracted": 0,
                "errors": 0,
                "validation_errors": 0,
                "dependency_errors": 0,
                "initialization_errors": 0,
                "cleanup_errors": 0,
                "state_errors": 0,
                "config_errors": 0,
                "computation_errors": 0,
                "io_errors": 0,
                "resource_errors": 0,
                "timeout_errors": 0
            }
            self.error_history: List[Dict[str, Any]] = []
            
            # Load configuration
            if self.enabled:
                try:
                    self._load_config()
                    self.logger.info(
                        "Basic metrics extractor initialized", 
                        min_packets_threshold=self.min_packets_for_valid_ratios
                    )
                except Exception as e:
                    self._update_stats("config_errors")
                    raise BasicMetricsConfigError(f"Configuration loading failed: {str(e)}")
            
        except Exception as e:
            error_msg = f"Failed to initialize basic metrics extractor: {str(e)}"
            self.logger.error(error_msg)
            raise BasicMetricsInitializationError(error_msg) from e
    
    def _load_config(self) -> None:
        """
        Load feature-specific configuration.
        
        Raises:
            BasicMetricsConfigError: If configuration loading fails
        """
        try:
            # Get the minimum packet threshold for calculating ratios
            self.min_packets_for_valid_ratios = int(self.feature_config.get(
                'min_packets_for_valid_ratios', 10
            ))
            
            # Validate configuration values
            if self.min_packets_for_valid_ratios <= 0:
                raise BasicMetricsConfigError("min_packets_for_valid_ratios must be positive")
            
        except Exception as e:
            self._update_stats("config_errors")
            raise BasicMetricsConfigError(f"Configuration validation failed: {str(e)}")
    
    def _validate_state(self) -> None:
        """
        Validate current state of the extractor.
        
        Raises:
            BasicMetricsStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if self.running and not self.initialized:
                    raise BasicMetricsStateError("Running state but not initialized")
                if not self.running and self.initialized:
                    raise BasicMetricsStateError("Not running but initialized")
                if self._is_shutting_down and self.running:
                    raise BasicMetricsStateError("Shutting down but still running")
        except Exception as e:
            self._update_stats("state_errors")
            raise BasicMetricsStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """
        Update extractor state with error handling.
        
        Args:
            new_state: New state to set
            
        Raises:
            BasicMetricsStateError: If state update fails
        """
        try:
            with self.state_lock:
                old_state = self.running
                self.running = new_state
                
                if old_state != new_state:
                    self.logger.info(
                        "Extractor state changed",
                        extractor=self.feature_name,
                        old_state=old_state,
                        new_state=new_state
                    )
        except Exception as e:
            self._update_stats("state_errors")
            raise BasicMetricsStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
            
        Raises:
            BasicMetricsStatsError: If statistics update fails
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            raise BasicMetricsStatsError(f"Failed to update statistics: {str(e)}")
    
    def _handle_error(self, error: Exception, context: str,
                     severity: str = "error", stat_key: str = "errors") -> None:
        """
        Handle errors with error handling.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            severity: Error severity ('error' or 'warning')
            stat_key: Statistics key to update
            
        Raises:
            BasicMetricsError: If error handling fails
        """
        try:
            # Update error statistics
            with self.stats_lock:
                self.stats[stat_key] += 1
                self.error_history.append({
                    "time": time.time(),
                    "context": context,
                    "error": str(error),
                    "type": type(error).__name__,
                    "severity": severity
                })
                
                # Keep only the last 100 errors
                if len(self.error_history) > 100:
                    self.error_history = self.error_history[-100:]
            
            # Log error
            log_method = getattr(self.logger, severity)
            log_method(
                f"Error in {context}",
                extractor=self.feature_name,
                error=str(error),
                error_type=type(error).__name__,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            raise BasicMetricsError(f"Error handling failed: {str(e)}") from e
    
    def _initialize(self) -> bool:
        """
        Perform feature-specific initialization.
        
        Returns:
            True if initialization successful, False otherwise
            
        Raises:
            BasicMetricsInitializationError: If initialization fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.initialized:
                self.logger.warning("Basic metrics extractor already initialized")
                return True
            
            # Initialize resources
            try:
                # No specific initialization needed for basic metrics
                self.initialized = True
                self._update_state(True)
                self.logger.info("Basic metrics extractor initialized successfully")
                return True
            except Exception as e:
                self._update_stats("initialization_errors")
                raise BasicMetricsInitializationError(f"Initialization failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "initialize", "error", "initialization_errors")
            return False
    
    def _cleanup(self) -> None:
        """
        Perform feature-specific cleanup.
        
        Raises:
            BasicMetricsCleanupError: If cleanup fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.initialized:
                self.logger.warning("Basic metrics extractor not initialized")
                return
            
            # Update state first
            self._update_state(False)
            self._is_shutting_down = True
            
            # Cleanup resources
            try:
                # No specific cleanup needed for basic metrics
                self.initialized = False
                self.logger.info("Basic metrics extractor cleaned up successfully")
            except Exception as e:
                self._update_stats("cleanup_errors")
                raise BasicMetricsCleanupError(f"Cleanup failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "cleanup", "error", "cleanup_errors")
            raise BasicMetricsCleanupError(f"Cleanup failed: {str(e)}")
    
    def _calculate_entropy(self, distribution: Dict[int, int]) -> float:
        """
        Calculate Shannon entropy of a distribution.
        
        Args:
            distribution: Dictionary mapping values to counts
            
        Returns:
            Entropy value
            
        Raises:
            BasicMetricsError: If entropy calculation fails
        """
        try:
            total = sum(distribution.values())
            if total == 0:
                return 0
                
            entropy = 0
            for count in distribution.values():
                if count > 0:
                    p = count / total
                    entropy -= p * math.log2(p)
                    
            return entropy
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_entropy", "error", "errors")
            return 0.0
    
    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract basic metrics features from a flow.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dictionary of extracted features
            
        Raises:
            BasicMetricsError: If feature extraction fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                return {}
            
            features = {}
            
            # Get basic flow metrics directly from flow data
            try:
                # Flow duration
                features["flow_duration"] = flow_data.get("flow_duration", 0)
                
                # Basic packet and byte counts
                fwd_packets = flow_data.get("total_fwd_packets", 0)
                bwd_packets = flow_data.get("total_bwd_packets", 0)
                fwd_bytes = flow_data.get("total_length_of_fwd_packets", 0)
                bwd_bytes = flow_data.get("total_length_of_bwd_packets", 0)
                
                total_packets = fwd_packets + bwd_packets
                total_bytes = fwd_bytes + bwd_bytes
                
                features["total_fwd_packets"] = fwd_packets
                features["total_bwd_packets"] = bwd_packets
                features["total_packets"] = total_packets
                features["total_length_of_fwd_packets"] = fwd_bytes
                features["total_length_of_bwd_packets"] = bwd_bytes
                features["total_bytes"] = total_bytes
            except Exception as e:
                self._update_stats("computation_errors")
                raise BasicMetricsError(f"Failed to extract basic flow metrics: {str(e)}")
            
            # Flow rate metrics - handle division by zero
            try:
                duration = max(flow_data.get("flow_duration", 0), 0.001)  # Prevent division by zero
                
                flow_bytes_per_sec = total_bytes / duration
                flow_packets_per_sec = total_packets / duration
                fwd_bytes_per_sec = fwd_bytes / duration
                bwd_bytes_per_sec = bwd_bytes / duration
                fwd_packets_per_sec = fwd_packets / duration
                bwd_packets_per_sec = bwd_packets / duration
                
                features["flow_bytes_per_sec"] = flow_bytes_per_sec
                features["flow_packets_per_sec"] = flow_packets_per_sec
                features["fwd_bytes_per_sec"] = fwd_bytes_per_sec
                features["bwd_bytes_per_sec"] = bwd_bytes_per_sec
                features["fwd_packets_per_sec"] = fwd_packets_per_sec
                features["bwd_packets_per_sec"] = bwd_packets_per_sec
            except Exception as e:
                self._update_stats("computation_errors")
                raise BasicMetricsError(f"Failed to calculate flow rate metrics: {str(e)}")
            
            # Calculate ratios - only if enough packets are present
            try:
                if total_packets >= self.min_packets_for_valid_ratios:
                    # Down/up ratio (bwd/fwd bytes)
                    down_up_ratio = bwd_bytes / max(fwd_bytes, 1)  # Prevent division by zero
                    features["down_up_ratio"] = down_up_ratio
                    
                    # Packet size ratio (avg bwd packet size / avg fwd packet size)
                    avg_fwd_packet_size = fwd_bytes / max(fwd_packets, 1)
                    avg_bwd_packet_size = bwd_bytes / max(bwd_packets, 1)
                    packet_size_ratio = avg_bwd_packet_size / max(avg_fwd_packet_size, 1)
                    features["packet_size_ratio"] = packet_size_ratio
                    
                    # Packet count ratio (bwd/fwd packets)
                    packet_count_ratio = bwd_packets / max(fwd_packets, 1)
                    features["packet_count_ratio"] = packet_count_ratio
                    
                    # Calculate bytes ratio variance
                    # This measures the consistency of transfer direction
                    if fwd_packets > 0 and bwd_packets > 0:
                        bytes_per_packet_fwd = fwd_bytes / fwd_packets
                        bytes_per_packet_bwd = bwd_bytes / bwd_packets
                        bytes_ratio_variance = abs(bytes_per_packet_fwd - bytes_per_packet_bwd) / max(bytes_per_packet_fwd, bytes_per_packet_bwd)
                        features["bytes_ratio_variance"] = bytes_ratio_variance
                    else:
                        features["bytes_ratio_variance"] = 0
                else:
                    # Not enough packets for meaningful ratios
                    features["down_up_ratio"] = 0
                    features["packet_size_ratio"] = 0
                    features["packet_count_ratio"] = 0
                    features["bytes_ratio_variance"] = 0
            except Exception as e:
                self._update_stats("computation_errors")
                raise BasicMetricsError(f"Failed to calculate transfer ratios: {str(e)}")
            
            # Calculate average packet sizes
            try:
                if total_packets > 0:
                    features["average_packet_size"] = total_bytes / total_packets
                else:
                    features["average_packet_size"] = 0
                    
                features["avg_fwd_segment_size"] = fwd_bytes / max(fwd_packets, 1)
                features["avg_bwd_segment_size"] = bwd_bytes / max(bwd_packets, 1)
            except Exception as e:
                self._update_stats("computation_errors")
                raise BasicMetricsError(f"Failed to calculate average packet sizes: {str(e)}")
            
            # Calculate packet size entropy if we have packet size distribution
            try:
                if "packet_length_distribution" in flow_data:
                    packet_length_distribution = flow_data["packet_length_distribution"]
                    entropy = self._calculate_entropy(packet_length_distribution)
                    features["packet_size_entropy"] = entropy
                else:
                    # Approximate entropy from standard deviation if available
                    packet_length_std = flow_data.get("packet_length_std", 0)
                    if packet_length_std > 0:
                        # Rough approximation - higher std indicates more randomness
                        features["packet_size_entropy"] = math.log(1 + packet_length_std)
                    else:
                        features["packet_size_entropy"] = 0
            except Exception as e:
                self._update_stats("computation_errors")
                raise BasicMetricsError(f"Failed to calculate packet size entropy: {str(e)}")
            
            self._update_stats("features_extracted")
            return features
            
        except Exception as e:
            self._handle_error(e, "extract_features", "error", "errors")
            raise BasicMetricsError(f"Feature extraction failed: {str(e)}")
