"""
Packet Length feature extractor for the Network Feature Extractor.
Analyzes packet length distributions and statistics with enhanced error handling and performance monitoring.
"""

import math
import numpy as np
from typing import Dict, Any, List, Optional
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


class PacketLengthError(FeatureError):
    """Base exception for packet length errors."""
    pass


class PacketLengthInitializationError(FeatureInitializationError):
    """Exception raised during packet length initialization."""
    pass


class PacketLengthCleanupError(FeatureCleanupError):
    """Exception raised during packet length cleanup."""
    pass


class PacketLengthStatsError(FeatureStatsError):
    """Exception raised during packet length statistics management."""
    pass


class PacketLengthConfigError(FeatureConfigError):
    """Exception raised during packet length configuration validation."""
    pass


class PacketLengthStateError(FeatureStateError):
    """Exception raised during packet length state management."""
    pass


class PacketLengthIOError(FeatureIOError):
    """Exception raised during packet length I/O operations."""
    pass


class PacketLengthResourceError(FeatureResourceError):
    """Exception raised when packet length resource limits are exceeded."""
    pass


class PacketLengthTimeoutError(FeatureTimeoutError):
    """Exception raised when packet length operations timeout."""
    pass


class PacketLengthExtractor(BaseFeatureExtractor):
    """
    Packet Length feature extractor.
    
    Extracts the following features:
    - Packet length statistics (min, max, mean, std)
    - Histograms of packet lengths
    - Advanced packet length metrics
    """
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the packet length extractor.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            
        Raises:
            PacketLengthInitializationError: If initialization fails
        """
        try:
            super().__init__(config, logger_manager, 'packet_length')
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.running = False
            self.initialized = False
            self._is_shutting_down = False
            
            # Default histogram bins
            self.histogram_bin_count = 10
            self.min_packet_length = 0
            self.max_packet_length = 1500  # Typical MTU
            self.quantile_levels = [0.1, 0.25, 0.5, 0.75, 0.9]
            self.store_histograms = False
            
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
                        "Packet length extractor initialized", 
                        histogram_bins=self.histogram_bin_count,
                        min_packet_length=self.min_packet_length,
                        max_packet_length=self.max_packet_length
                    )
                except Exception as e:
                    self._update_stats("config_errors")
                    raise PacketLengthConfigError(f"Configuration loading failed: {str(e)}")
            
        except Exception as e:
            error_msg = f"Failed to initialize packet length extractor: {str(e)}"
            self.logger.error(error_msg)
            raise PacketLengthInitializationError(error_msg) from e
    
    def _load_config(self) -> None:
        """
        Load feature-specific configuration.
        
        Raises:
            PacketLengthConfigError: If configuration loading fails
        """
        try:
            # Get histogram configurations
            self.histogram_bin_count = int(self.feature_config.get(
                'histogram_bins', 10
            ))
            self.min_packet_length = int(self.feature_config.get(
                'min_packet_length', 0
            ))
            self.max_packet_length = int(self.feature_config.get(
                'max_packet_length', 1500
            ))
            self.quantile_levels = self.feature_config.get(
                'quantile_levels', [0.1, 0.25, 0.5, 0.75, 0.9]
            )
            self.store_histograms = bool(self.feature_config.get(
                'store_histograms', False
            ))
            
            # Validate configuration values
            if self.histogram_bin_count <= 0:
                raise PacketLengthConfigError("histogram_bins must be positive")
            if self.min_packet_length < 0:
                raise PacketLengthConfigError("min_packet_length must be non-negative")
            if self.max_packet_length <= self.min_packet_length:
                raise PacketLengthConfigError("max_packet_length must be greater than min_packet_length")
            if not all(0 < q < 1 for q in self.quantile_levels):
                raise PacketLengthConfigError("quantile_levels must be between 0 and 1")
            
        except Exception as e:
            self._update_stats("config_errors")
            raise PacketLengthConfigError(f"Configuration validation failed: {str(e)}")
    
    def _validate_state(self) -> None:
        """
        Validate current state of the extractor.
        
        Raises:
            PacketLengthStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if self.running and not self.initialized:
                    raise PacketLengthStateError("Running state but not initialized")
                if not self.running and self.initialized:
                    raise PacketLengthStateError("Not running but initialized")
                if self._is_shutting_down and self.running:
                    raise PacketLengthStateError("Shutting down but still running")
        except Exception as e:
            self._update_stats("state_errors")
            raise PacketLengthStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """
        Update extractor state with error handling.
        
        Args:
            new_state: New state to set
            
        Raises:
            PacketLengthStateError: If state update fails
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
            raise PacketLengthStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
            
        Raises:
            PacketLengthStatsError: If statistics update fails
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            raise PacketLengthStatsError(f"Failed to update statistics: {str(e)}")
    
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
            PacketLengthError: If error handling fails
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
            raise PacketLengthError(f"Error handling failed: {str(e)}") from e
    
    def _initialize(self) -> bool:
        """
        Perform feature-specific initialization.
        
        Returns:
            True if initialization successful, False otherwise
            
        Raises:
            PacketLengthInitializationError: If initialization fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.initialized:
                self.logger.warning("Packet length extractor already initialized")
                return True
            
            # Initialize resources
            try:
                # No specific initialization needed for packet length
                self.initialized = True
                self._update_state(True)
                self.logger.info("Packet length extractor initialized successfully")
                return True
            except Exception as e:
                self._update_stats("initialization_errors")
                raise PacketLengthInitializationError(f"Initialization failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "initialize", "error", "initialization_errors")
            return False
    
    def _cleanup(self) -> None:
        """
        Perform feature-specific cleanup.
        
        Raises:
            PacketLengthCleanupError: If cleanup fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.initialized:
                self.logger.warning("Packet length extractor not initialized")
                return
            
            # Update state first
            self._update_state(False)
            self._is_shutting_down = True
            
            # Cleanup resources
            try:
                # No specific cleanup needed for packet length
                self.initialized = False
                self.logger.info("Packet length extractor cleaned up successfully")
            except Exception as e:
                self._update_stats("cleanup_errors")
                raise PacketLengthCleanupError(f"Cleanup failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "cleanup", "error", "cleanup_errors")
            raise PacketLengthCleanupError(f"Cleanup failed: {str(e)}")
    
    def _get_packet_lengths(self, flow_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract packet lengths from flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Array of packet lengths, or None if not available
            
        Raises:
            PacketLengthError: If packet length extraction fails
        """
        try:
            # Check if we have packet data with lengths
            if "packets" not in flow_data or not flow_data["packets"]:
                return None
            
            # Extract lengths from packets
            lengths = []
            for packet in flow_data["packets"]:
                if "length" in packet:
                    lengths.append(packet["length"])
            
            return np.array(lengths) if lengths else None
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "get_packet_lengths", "error", "errors")
            return None
    
    def _calculate_skewness(self, data: np.ndarray) -> float:
        """
        Calculate skewness of packet lengths.
        
        Args:
            data: Array of packet lengths
            
        Returns:
            Skewness value
            
        Raises:
            PacketLengthError: If skewness calculation fails
        """
        try:
            if len(data) < 3:
                return 0.0
            
            mean = np.mean(data)
            std = np.std(data)
            
            if std == 0:
                return 0.0
            
            # Calculate 3rd standardized moment
            skew = np.mean(((data - mean) / std) ** 3)
            return skew
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_skewness", "error", "errors")
            return 0.0
    
    def _calculate_kurtosis(self, data: np.ndarray) -> float:
        """
        Calculate kurtosis of packet lengths.
        
        Args:
            data: Array of packet lengths
            
        Returns:
            Kurtosis value
            
        Raises:
            PacketLengthError: If kurtosis calculation fails
        """
        try:
            if len(data) < 4:
                return 0.0
            
            mean = np.mean(data)
            std = np.std(data)
            
            if std == 0:
                return 0.0
            
            # Calculate 4th standardized moment
            kurtosis = np.mean(((data - mean) / std) ** 4)
            return kurtosis
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_kurtosis", "error", "errors")
            return 0.0
    
    def _calculate_quantiles(self, data: np.ndarray, quantiles: List[float]) -> List[float]:
        """
        Calculate quantiles of packet lengths.
        
        Args:
            data: Array of packet lengths
            quantiles: List of quantile levels
            
        Returns:
            List of quantile values
            
        Raises:
            PacketLengthError: If quantile calculation fails
        """
        try:
            if len(data) < 2:
                return [0.0] * len(quantiles)
            
            return [np.percentile(data, q * 100) for q in quantiles]
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_quantiles", "error", "errors")
            return [0.0] * len(quantiles)
    
    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract packet length features from a flow.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dictionary of extracted features
            
        Raises:
            PacketLengthError: If feature extraction fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                return {}
            
            features = {}
            
            # Extract already calculated packet length statistics
            try:
                features["fwd_packet_length_max"] = flow_data.get("fwd_packet_length_max", 0)
                features["fwd_packet_length_min"] = flow_data.get("fwd_packet_length_min", 0)
                features["fwd_packet_length_mean"] = flow_data.get("fwd_packet_length_mean", 0)
                features["fwd_packet_length_std"] = flow_data.get("fwd_packet_length_std", 0)
                features["bwd_packet_length_max"] = flow_data.get("bwd_packet_length_max", 0)
                features["bwd_packet_length_min"] = flow_data.get("bwd_packet_length_min", 0)
                features["bwd_packet_length_mean"] = flow_data.get("bwd_packet_length_mean", 0)
                features["bwd_packet_length_std"] = flow_data.get("bwd_packet_length_std", 0)
            except Exception as e:
                self._update_stats("computation_errors")
                raise PacketLengthError(f"Failed to extract basic packet length statistics: {str(e)}")
            
            # Calculate combined packet length statistics
            try:
                fwd_bytes = flow_data.get("total_length_of_fwd_packets", 0)
                bwd_bytes = flow_data.get("total_length_of_bwd_packets", 0)
                fwd_packets = flow_data.get("total_fwd_packets", 0)
                bwd_packets = flow_data.get("total_bwd_packets", 0)
                total_packets = fwd_packets + bwd_packets
                
                # Overall packet length variance - already calculated in Flow
                features["packet_length_variance"] = flow_data.get("packet_length_variance", 0)
                features["packet_length_std"] = math.sqrt(max(0, features["packet_length_variance"]))
                
                # Calculate overall max, min, mean packet lengths
                if fwd_packets > 0 and bwd_packets > 0:
                    features["packet_length_max"] = max(
                        features["fwd_packet_length_max"], 
                        features["bwd_packet_length_max"]
                    )
                    features["packet_length_min"] = min(
                        features["fwd_packet_length_min"], 
                        features["bwd_packet_length_min"]
                    )
                    
                    # Calculate weighted mean of forward and backward packet lengths
                    total_bytes = fwd_bytes + bwd_bytes
                    if total_packets > 0:
                        features["packet_length_mean"] = total_bytes / total_packets
                    else:
                        features["packet_length_mean"] = 0
                elif fwd_packets > 0:
                    features["packet_length_max"] = features["fwd_packet_length_max"]
                    features["packet_length_min"] = features["fwd_packet_length_min"]
                    features["packet_length_mean"] = features["fwd_packet_length_mean"]
                elif bwd_packets > 0:
                    features["packet_length_max"] = features["bwd_packet_length_max"]
                    features["packet_length_min"] = features["bwd_packet_length_min"]
                    features["packet_length_mean"] = features["bwd_packet_length_mean"]
                else:
                    features["packet_length_max"] = 0
                    features["packet_length_min"] = 0
                    features["packet_length_mean"] = 0
            except Exception as e:
                self._update_stats("computation_errors")
                raise PacketLengthError(f"Failed to calculate combined packet length statistics: {str(e)}")
            
            # Calculate advanced packet length metrics
            try:
                packet_length_mean = features["packet_length_mean"]
                packet_length_variance = features["packet_length_variance"]
                
                # Variance to mean ratio (index of dispersion)
                if packet_length_mean > 0:
                    features["packet_length_variance_to_mean_ratio"] = packet_length_variance / packet_length_mean
                else:
                    features["packet_length_variance_to_mean_ratio"] = 0
                
                # Coefficient of variation
                if packet_length_mean > 0:
                    features["packet_length_coefficient_of_variation"] = features["packet_length_std"] / packet_length_mean
                else:
                    features["packet_length_coefficient_of_variation"] = 0
            except Exception as e:
                self._update_stats("computation_errors")
                raise PacketLengthError(f"Failed to calculate advanced packet length metrics: {str(e)}")
            
            # If we have packet length array, calculate higher order statistics
            try:
                packet_lengths = self._get_packet_lengths(flow_data)
                
                if packet_lengths is not None and len(packet_lengths) >= 4:  # Need at least 4 packets for meaningful stats
                    # Calculate skewness - 3rd standardized moment
                    skew = self._calculate_skewness(packet_lengths)
                    features["packet_length_skew"] = skew
                    
                    # Calculate kurtosis - 4th standardized moment
                    kurtosis = self._calculate_kurtosis(packet_lengths)
                    features["packet_length_kurtosis"] = kurtosis
                    
                    # Calculate quantiles
                    quantiles = self._calculate_quantiles(packet_lengths, self.quantile_levels)
                    
                    # Store median (50th percentile)
                    median_idx = self.quantile_levels.index(0.5) if 0.5 in self.quantile_levels else -1
                    if median_idx >= 0:
                        features["packet_length_median"] = quantiles[median_idx]
                    else:
                        features["packet_length_median"] = np.median(packet_lengths)
                    
                    # Store inter-quartile range (75th - 25th percentile)
                    q25_idx = self.quantile_levels.index(0.25) if 0.25 in self.quantile_levels else -1
                    q75_idx = self.quantile_levels.index(0.75) if 0.75 in self.quantile_levels else -1
                    
                    if q25_idx >= 0 and q75_idx >= 0:
                        features["packet_length_iqr"] = quantiles[q75_idx] - quantiles[q25_idx]
                    else:
                        q75 = np.percentile(packet_lengths, 75)
                        q25 = np.percentile(packet_lengths, 25)
                        features["packet_length_iqr"] = q75 - q25
                    
                    # Store all quantiles
                    for i, q in enumerate(self.quantile_levels):
                        q_str = str(int(q * 100))
                        features[f"packet_length_q{q_str}"] = quantiles[i]
                    
                    # Calculate histogram
                    hist, bin_edges = np.histogram(
                        packet_lengths, 
                        bins=self.histogram_bin_count, 
                        range=(self.min_packet_length, self.max_packet_length)
                    )
                    
                    # Normalize histogram to get probabilities
                    hist_norm = hist / len(packet_lengths)
                    
                    # Store histogram bins if configured
                    if self.store_histograms:
                        for i in range(self.histogram_bin_count):
                            features[f"packet_length_hist_bin_{i}"] = hist_norm[i]
                else:
                    # Not enough data for advanced statistics
                    features["packet_length_skew"] = 0
                    features["packet_length_kurtosis"] = 0
                    features["packet_length_median"] = 0
                    features["packet_length_iqr"] = 0
                    for q in self.quantile_levels:
                        q_str = str(int(q * 100))
                        features[f"packet_length_q{q_str}"] = 0
                    if self.store_histograms:
                        for i in range(self.histogram_bin_count):
                            features[f"packet_length_hist_bin_{i}"] = 0
            except Exception as e:
                self._update_stats("computation_errors")
                raise PacketLengthError(f"Failed to calculate higher order statistics: {str(e)}")
            
            # Update statistics
            self._update_stats("features_extracted")
            return features
            
        except Exception as e:
            self._handle_error(e, "extract_features", "error", "errors")
            raise PacketLengthError(f"Feature extraction failed: {str(e)}")
