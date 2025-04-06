"""
Timing Metrics feature extractor for the Network Feature Extractor.
Analyzes timing patterns and inter-arrival times in network flows with enhanced error handling and performance monitoring.
"""

import math
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, Counter
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


class TimingMetricsError(FeatureError):
    """Base exception for timing metrics errors."""
    pass


class TimingMetricsInitializationError(FeatureInitializationError):
    """Exception raised during timing metrics initialization."""
    pass


class TimingMetricsCleanupError(FeatureCleanupError):
    """Exception raised during timing metrics cleanup."""
    pass


class TimingMetricsStatsError(FeatureStatsError):
    """Exception raised during timing metrics statistics management."""
    pass


class TimingMetricsConfigError(FeatureConfigError):
    """Exception raised during timing metrics configuration validation."""
    pass


class TimingMetricsStateError(FeatureStateError):
    """Exception raised during timing metrics state management."""
    pass


class TimingMetricsIOError(FeatureIOError):
    """Exception raised during timing metrics I/O operations."""
    pass


class TimingMetricsResourceError(FeatureResourceError):
    """Exception raised when timing metrics resource limits are exceeded."""
    pass


class TimingMetricsTimeoutError(FeatureTimeoutError):
    """Exception raised when timing metrics operations timeout."""
    pass


class TimingMetricsExtractor(BaseFeatureExtractor):
    """
    Timing Metrics feature extractor.
    
    Extracts the following features:
    - Inter-arrival time (IAT) statistics
    - Flow duration and timing patterns
    - Active/idle time analysis
    - Periodicity detection
    """
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the timing metrics extractor.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            
        Raises:
            TimingMetricsInitializationError: If initialization fails
        """
        try:
            super().__init__(config, logger_manager, 'timing_metrics')
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.running = False
            self.initialized = False
            self._is_shutting_down = False
            
            # Default settings
            self.activity_timeout = 1.0  # seconds
            self.fft_enabled = False
            self.max_periodicity_bins = 10
            self.min_points_for_periodicity = 20
            self.burst_threshold = 0.1  # seconds
            
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
                        "Timing metrics extractor initialized", 
                        activity_timeout=self.activity_timeout,
                        fft_enabled=self.fft_enabled
                    )
                except Exception as e:
                    self._update_stats("config_errors")
                    raise TimingMetricsConfigError(f"Configuration loading failed: {str(e)}")
            
        except Exception as e:
            error_msg = f"Failed to initialize timing metrics extractor: {str(e)}"
            self.logger.error(error_msg)
            raise TimingMetricsInitializationError(error_msg) from e
    
    def _load_config(self) -> None:
        """
        Load feature-specific configuration.
        
        Raises:
            TimingMetricsConfigError: If configuration loading fails
        """
        try:
            # Get timing metrics configurations
            self.activity_timeout = float(self.feature_config.get(
                'activity_timeout', 1.0
            ))
            self.fft_enabled = bool(self.feature_config.get(
                'fft_enabled', False
            ))
            self.max_periodicity_bins = int(self.feature_config.get(
                'max_periodicity_bins', 10
            ))
            self.min_points_for_periodicity = int(self.feature_config.get(
                'min_points_for_periodicity', 20
            ))
            self.burst_threshold = float(self.feature_config.get(
                'burst_threshold', 0.1
            ))
            
            # Validate configuration values
            if self.activity_timeout <= 0:
                raise TimingMetricsConfigError("activity_timeout must be positive")
            if self.max_periodicity_bins <= 0:
                raise TimingMetricsConfigError("max_periodicity_bins must be positive")
            if self.min_points_for_periodicity <= 0:
                raise TimingMetricsConfigError("min_points_for_periodicity must be positive")
            if self.burst_threshold <= 0:
                raise TimingMetricsConfigError("burst_threshold must be positive")
            
        except Exception as e:
            self._update_stats("config_errors")
            raise TimingMetricsConfigError(f"Configuration validation failed: {str(e)}")
    
    def _validate_state(self) -> None:
        """
        Validate current state of the extractor.
        
        Raises:
            TimingMetricsStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if self.running and not self.initialized:
                    raise TimingMetricsStateError("Running state but not initialized")
                if not self.running and self.initialized:
                    raise TimingMetricsStateError("Not running but initialized")
                if self._is_shutting_down and self.running:
                    raise TimingMetricsStateError("Shutting down but still running")
        except Exception as e:
            self._update_stats("state_errors")
            raise TimingMetricsStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """
        Update extractor state with error handling.
        
        Args:
            new_state: New state to set
            
        Raises:
            TimingMetricsStateError: If state update fails
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
            raise TimingMetricsStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
            
        Raises:
            TimingMetricsStatsError: If statistics update fails
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            raise TimingMetricsStatsError(f"Failed to update statistics: {str(e)}")
    
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
            TimingMetricsError: If error handling fails
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
            raise TimingMetricsError(f"Error handling failed: {str(e)}") from e
    
    def _initialize(self) -> bool:
        """
        Perform feature-specific initialization.
        
        Returns:
            True if initialization successful, False otherwise
            
        Raises:
            TimingMetricsInitializationError: If initialization fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.initialized:
                self.logger.warning("Timing metrics extractor already initialized")
                return True
            
            # Initialize numpy arrays and other resources
            try:
                # No specific initialization needed for timing metrics
                self.initialized = True
                self._update_state(True)
                self.logger.info("Timing metrics extractor initialized successfully")
                return True
            except Exception as e:
                self._update_stats("initialization_errors")
                raise TimingMetricsInitializationError(f"Initialization failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "initialize", "error", "initialization_errors")
            return False
    
    def _cleanup(self) -> None:
        """
        Perform feature-specific cleanup.
        
        Raises:
            TimingMetricsCleanupError: If cleanup fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.initialized:
                self.logger.warning("Timing metrics extractor not initialized")
                return
            
            # Update state first
            self._update_state(False)
            self._is_shutting_down = True
            
            # Cleanup resources
            try:
                # No specific cleanup needed for timing metrics
                self.initialized = False
                self.logger.info("Timing metrics extractor cleaned up successfully")
            except Exception as e:
                self._update_stats("cleanup_errors")
                raise TimingMetricsCleanupError(f"Cleanup failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "cleanup", "error", "cleanup_errors")
            raise TimingMetricsCleanupError(f"Cleanup failed: {str(e)}")
    
    def _extract_timestamps(self, flow_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract timestamps from flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Array of timestamps if available, None otherwise
            
        Raises:
            TimingMetricsError: If timestamp extraction fails
        """
        try:
            timestamps = flow_data.get("timestamps")
            if timestamps is None:
                return None
            
            # Convert to numpy array and validate
            try:
                timestamps_array = np.array(timestamps, dtype=np.float64)
                if len(timestamps_array) == 0:
                    return None
                if not np.all(np.isfinite(timestamps_array)):
                    self._update_stats("validation_errors")
                    return None
                return timestamps_array
            except Exception as e:
                self._update_stats("validation_errors")
                raise TimingMetricsError(f"Failed to convert timestamps to array: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "extract_timestamps", "error", "errors")
            return None
    
    def _calculate_skewness(self, data: np.ndarray) -> float:
        """
        Calculate skewness of data.
        
        Args:
            data: Input data array
            
        Returns:
            Skewness value
            
        Raises:
            TimingMetricsError: If calculation fails
        """
        try:
            if len(data) < 3:
                return 0.0
            
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0.0
            
            return np.mean(((data - mean) / std) ** 3)
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_skewness", "error", "errors")
            return 0.0
    
    def _calculate_kurtosis(self, data: np.ndarray) -> float:
        """
        Calculate kurtosis of data.
        
        Args:
            data: Input data array
            
        Returns:
            Kurtosis value
            
        Raises:
            TimingMetricsError: If calculation fails
        """
        try:
            if len(data) < 4:
                return 0.0
            
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0.0
            
            return np.mean(((data - mean) / std) ** 4) - 3.0
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_kurtosis", "error", "errors")
            return 0.0
    
    def _detect_bursts(self, timestamps: np.ndarray) -> Tuple[List[List[int]], List[float]]:
        """
        Detect packet bursts in timestamp sequence.
        
        Args:
            timestamps: Array of packet timestamps
            
        Returns:
            Tuple of (burst indices, burst durations)
            
        Raises:
            TimingMetricsError: If burst detection fails
        """
        try:
            if len(timestamps) < 2:
                return [], []
            
            # Calculate inter-arrival times
            iat = np.diff(timestamps)
            
            # Find burst boundaries
            burst_indices = []
            current_burst = [0]
            
            for i in range(1, len(iat)):
                if iat[i] <= self.burst_threshold:
                    current_burst.append(i)
                else:
                    if len(current_burst) > 1:
                        burst_indices.append(current_burst)
                    current_burst = [i]
            
            if len(current_burst) > 1:
                burst_indices.append(current_burst)
            
            # Calculate burst durations
            burst_durations = []
            for burst in burst_indices:
                duration = timestamps[burst[-1]] - timestamps[burst[0]]
                burst_durations.append(duration)
            
            return burst_indices, burst_durations
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "detect_bursts", "error", "errors")
            return [], []
    
    def _calculate_sequence_complexity(self, iat_array: np.ndarray) -> float:
        """
        Calculate complexity of time sequence.
        
        Args:
            iat_array: Array of inter-arrival times
            
        Returns:
            Complexity score
            
        Raises:
            TimingMetricsError: If calculation fails
        """
        try:
            if len(iat_array) < 2:
                return 0.0
            
            # Calculate entropy of IAT distribution
            hist, _ = np.histogram(iat_array, bins=20, density=True)
            hist = hist[hist > 0]  # Remove zero bins
            if len(hist) == 0:
                return 0.0
            
            # Normalize histogram
            hist = hist / np.sum(hist)
            
            # Calculate entropy
            entropy = -np.sum(hist * np.log2(hist))
            
            # Normalize by maximum possible entropy
            max_entropy = np.log2(len(hist))
            if max_entropy == 0:
                return 0.0
            
            return entropy / max_entropy
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_sequence_complexity", "error", "errors")
            return 0.0
    
    def _detect_periodicity(self, timestamps: np.ndarray) -> Tuple[float, float, np.ndarray]:
        """
        Detect periodicity in timestamp sequence.
        
        Args:
            timestamps: Array of packet timestamps
            
        Returns:
            Tuple of (periodicity score, strongest period, period powers)
            
        Raises:
            TimingMetricsError: If periodicity detection fails
        """
        try:
            if len(timestamps) < self.min_points_for_periodicity:
                return 0.0, 0.0, np.zeros(self.max_periodicity_bins)
            
            # Calculate FFT
            fft_result = np.fft.fft(timestamps - timestamps[0])
            freqs = np.fft.fftfreq(len(timestamps))
            
            # Get magnitude spectrum
            magnitude = np.abs(fft_result)
            
            # Find peaks in magnitude spectrum
            peaks = []
            for i in range(1, len(magnitude) - 1):
                if magnitude[i] > magnitude[i-1] and magnitude[i] > magnitude[i+1]:
                    peaks.append((i, magnitude[i]))
            
            # Sort peaks by magnitude
            peaks.sort(key=lambda x: x[1], reverse=True)
            
            # Get top N peaks
            top_peaks = peaks[:self.max_periodicity_bins]
            
            # Calculate periodicity score
            if top_peaks:
                total_power = np.sum(magnitude)
                peak_power = sum(p[1] for p in top_peaks)
                periodicity_score = peak_power / total_power if total_power > 0 else 0
                
                # Get strongest period
                strongest_period = 1.0 / abs(freqs[top_peaks[0][0]]) if top_peaks[0][0] > 0 else 0
                
                # Get period powers
                period_powers = np.zeros(self.max_periodicity_bins)
                for i, (peak_idx, power) in enumerate(top_peaks):
                    period_powers[i] = power
                
                return periodicity_score, strongest_period, period_powers
            else:
                return 0.0, 0.0, np.zeros(self.max_periodicity_bins)
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "detect_periodicity", "error", "errors")
            return 0.0, 0.0, np.zeros(self.max_periodicity_bins)
    
    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract timing metrics features from a flow.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dictionary of extracted features
            
        Raises:
            TimingMetricsError: If feature extraction fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                return {}
            
            features = {}
            
            # Extract basic IAT statistics already calculated
            try:
                features["flow_iat_mean"] = flow_data.get("flow_iat_mean", 0)
                features["flow_iat_std"] = flow_data.get("flow_iat_std", 0)
                features["flow_iat_max"] = flow_data.get("flow_iat_max", 0)
                features["flow_iat_min"] = flow_data.get("flow_iat_min", 0)
                
                features["fwd_iat_total"] = flow_data.get("fwd_iat_total", 0)
                features["fwd_iat_mean"] = flow_data.get("fwd_iat_mean", 0)
                features["fwd_iat_std"] = flow_data.get("fwd_iat_std", 0)
                features["fwd_iat_max"] = flow_data.get("fwd_iat_max", 0)
                features["fwd_iat_min"] = flow_data.get("fwd_iat_min", 0)
                
                features["bwd_iat_total"] = flow_data.get("bwd_iat_total", 0)
                features["bwd_iat_mean"] = flow_data.get("bwd_iat_mean", 0)
                features["bwd_iat_std"] = flow_data.get("bwd_iat_std", 0)
                features["bwd_iat_max"] = flow_data.get("bwd_iat_max", 0)
                features["bwd_iat_min"] = flow_data.get("bwd_iat_min", 0)
            except Exception as e:
                self._update_stats("computation_errors")
                raise TimingMetricsError(f"Failed to extract basic IAT statistics: {str(e)}")
            
            # Calculate forward/backward IAT ratio
            try:
                fwd_iat_mean = features["fwd_iat_mean"]
                bwd_iat_mean = features["bwd_iat_mean"]
                if bwd_iat_mean > 0:
                    features["fwd_bwd_iat_ratio"] = fwd_iat_mean / bwd_iat_mean
                else:
                    features["fwd_bwd_iat_ratio"] = 0
            except Exception as e:
                self._update_stats("computation_errors")
                raise TimingMetricsError(f"Failed to calculate IAT ratio: {str(e)}")
            
            # Extract timestamps for advanced analysis
            try:
                timestamps = self._extract_timestamps(flow_data)
                if timestamps is not None:
                    # Calculate inter-arrival times
                    iat = np.diff(timestamps)
                    
                    # Calculate higher order statistics
                    features["iat_skewness"] = self._calculate_skewness(iat)
                    features["iat_kurtosis"] = self._calculate_kurtosis(iat)
                    
                    # Detect bursts
                    burst_indices, burst_durations = self._detect_bursts(timestamps)
                    if burst_durations:
                        features["burst_count"] = len(burst_durations)
                        features["burst_mean_duration"] = np.mean(burst_durations)
                        features["burst_std_duration"] = np.std(burst_durations)
                        features["burst_max_duration"] = np.max(burst_durations)
                        features["burst_min_duration"] = np.min(burst_durations)
                    else:
                        features["burst_count"] = 0
                        features["burst_mean_duration"] = 0
                        features["burst_std_duration"] = 0
                        features["burst_max_duration"] = 0
                        features["burst_min_duration"] = 0
                    
                    # Calculate sequence complexity
                    features["sequence_complexity"] = self._calculate_sequence_complexity(iat)
                    
                    # Detect periodicity if enabled
                    if self.fft_enabled:
                        periodicity_score, strongest_period, period_powers = self._detect_periodicity(timestamps)
                        features["periodicity_score"] = periodicity_score
                        features["strongest_period"] = strongest_period
                        for i in range(self.max_periodicity_bins):
                            features[f"period_power_{i}"] = period_powers[i]
            except Exception as e:
                self._update_stats("computation_errors")
                raise TimingMetricsError(f"Failed to perform advanced timing analysis: {str(e)}")
            
            # Update statistics
            self._update_stats("features_extracted")
            return features
            
        except Exception as e:
            self._handle_error(e, "extract_features", "error", "errors")
            raise TimingMetricsError(f"Feature extraction failed: {str(e)}")
