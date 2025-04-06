"""
Flag Analysis feature extractor for the Network Feature Extractor.
Analyzes TCP flag patterns and flag sequences with enhanced error handling and performance monitoring.
"""

from typing import Dict, Any, List, Set, Tuple, Optional
import math
from collections import Counter, defaultdict
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


class FlagAnalysisError(FeatureError):
    """Base exception for flag analysis errors."""
    pass


class FlagAnalysisInitializationError(FeatureInitializationError):
    """Exception raised during flag analysis initialization."""
    pass


class FlagAnalysisCleanupError(FeatureCleanupError):
    """Exception raised during flag analysis cleanup."""
    pass


class FlagAnalysisStatsError(FeatureStatsError):
    """Exception raised during flag analysis statistics management."""
    pass


class FlagAnalysisConfigError(FeatureConfigError):
    """Exception raised during flag analysis configuration validation."""
    pass


class FlagAnalysisStateError(FeatureStateError):
    """Exception raised during flag analysis state management."""
    pass


class FlagAnalysisIOError(FeatureIOError):
    """Exception raised during flag analysis I/O operations."""
    pass


class FlagAnalysisResourceError(FeatureResourceError):
    """Exception raised when flag analysis resource limits are exceeded."""
    pass


class FlagAnalysisTimeoutError(FeatureTimeoutError):
    """Exception raised when flag analysis operations timeout."""
    pass


class FlagAnalysisExtractor(BaseFeatureExtractor):
    """
    Flag Analysis feature extractor.
    
    Extracts the following features:
    - TCP flag counts
    - Flag combinations and sequences
    - Connection establishment and teardown patterns
    """
    
    # Flag definitions
    TCP_FIN = 0x01
    TCP_SYN = 0x02
    TCP_RST = 0x04
    TCP_PSH = 0x08
    TCP_ACK = 0x10
    TCP_URG = 0x20
    TCP_ECE = 0x40
    TCP_CWR = 0x80
    
    # Flag names for readability
    FLAG_NAMES = {
        TCP_FIN: 'FIN',
        TCP_SYN: 'SYN',
        TCP_RST: 'RST',
        TCP_PSH: 'PSH',
        TCP_ACK: 'ACK',
        TCP_URG: 'URG',
        TCP_ECE: 'ECE',
        TCP_CWR: 'CWR'
    }
    
    # Common flag combinations
    COMMON_COMBINATIONS = {
        # Connection establishment
        TCP_SYN: 'SYN',
        TCP_SYN | TCP_ACK: 'SYN-ACK',
        # Data transfer
        TCP_ACK: 'ACK',
        TCP_PSH | TCP_ACK: 'PSH-ACK',
        # Connection teardown
        TCP_FIN | TCP_ACK: 'FIN-ACK',
        # Error conditions
        TCP_RST: 'RST',
        TCP_RST | TCP_ACK: 'RST-ACK',
        # Congestion control
        TCP_ECE | TCP_ACK: 'ECE-ACK',
        TCP_CWR | TCP_ACK: 'CWR-ACK'
    }
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the flag analysis extractor.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            
        Raises:
            FlagAnalysisInitializationError: If initialization fails
        """
        try:
            super().__init__(config, logger_manager, 'flag_analysis')
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.running = False
            self.initialized = False
            self._is_shutting_down = False
            
            # Default settings
            self.analyze_sequences = True
            self.max_sequence_length = 5
            self.max_combinations = 10
            
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
                        "Flag analysis extractor initialized", 
                        analyze_sequences=self.analyze_sequences,
                        max_sequence_length=self.max_sequence_length
                    )
                except Exception as e:
                    self._update_stats("config_errors")
                    raise FlagAnalysisConfigError(f"Configuration loading failed: {str(e)}")
            
        except Exception as e:
            error_msg = f"Failed to initialize flag analysis extractor: {str(e)}"
            self.logger.error(error_msg)
            raise FlagAnalysisInitializationError(error_msg) from e
    
    def _load_config(self) -> None:
        """
        Load feature-specific configuration.
        
        Raises:
            FlagAnalysisConfigError: If configuration loading fails
        """
        try:
            # Get flag analysis configurations
            self.analyze_sequences = bool(self.feature_config.get(
                'analyze_sequences', True
            ))
            self.max_sequence_length = int(self.feature_config.get(
                'max_sequence_length', 5
            ))
            self.max_combinations = int(self.feature_config.get(
                'max_combinations', 10
            ))
            
            # Validate configuration values
            if self.max_sequence_length <= 0:
                raise FlagAnalysisConfigError("max_sequence_length must be positive")
            if self.max_combinations <= 0:
                raise FlagAnalysisConfigError("max_combinations must be positive")
            
        except Exception as e:
            self._update_stats("config_errors")
            raise FlagAnalysisConfigError(f"Configuration validation failed: {str(e)}")
    
    def _validate_state(self) -> None:
        """
        Validate current state of the extractor.
        
        Raises:
            FlagAnalysisStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if self.running and not self.initialized:
                    raise FlagAnalysisStateError("Running state but not initialized")
                if not self.running and self.initialized:
                    raise FlagAnalysisStateError("Not running but initialized")
                if self._is_shutting_down and self.running:
                    raise FlagAnalysisStateError("Shutting down but still running")
        except Exception as e:
            self._update_stats("state_errors")
            raise FlagAnalysisStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """
        Update extractor state with error handling.
        
        Args:
            new_state: New state to set
            
        Raises:
            FlagAnalysisStateError: If state update fails
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
            raise FlagAnalysisStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
            
        Raises:
            FlagAnalysisStatsError: If statistics update fails
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            raise FlagAnalysisStatsError(f"Failed to update statistics: {str(e)}")
    
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
            FlagAnalysisError: If error handling fails
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
            raise FlagAnalysisError(f"Error handling failed: {str(e)}") from e
    
    def _initialize(self) -> bool:
        """
        Perform feature-specific initialization.
        
        Returns:
            True if initialization successful, False otherwise
            
        Raises:
            FlagAnalysisInitializationError: If initialization fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.initialized:
                self.logger.warning("Flag analysis extractor already initialized")
                return True
            
            # Initialize resources
            try:
                # No specific initialization needed for flag analysis
                self.initialized = True
                self._update_state(True)
                self.logger.info("Flag analysis extractor initialized successfully")
                return True
            except Exception as e:
                self._update_stats("initialization_errors")
                raise FlagAnalysisInitializationError(f"Initialization failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "initialize", "error", "initialization_errors")
            return False
    
    def _cleanup(self) -> None:
        """
        Perform feature-specific cleanup.
        
        Raises:
            FlagAnalysisCleanupError: If cleanup fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.initialized:
                self.logger.warning("Flag analysis extractor not initialized")
                return
            
            # Update state first
            self._update_state(False)
            self._is_shutting_down = True
            
            # Cleanup resources
            try:
                # No specific cleanup needed for flag analysis
                self.initialized = False
                self.logger.info("Flag analysis extractor cleaned up successfully")
            except Exception as e:
                self._update_stats("cleanup_errors")
                raise FlagAnalysisCleanupError(f"Cleanup failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "cleanup", "error", "cleanup_errors")
            raise FlagAnalysisCleanupError(f"Cleanup failed: {str(e)}")
    
    def _extract_flag_combinations(self, flow_data: Dict[str, Any]) -> Optional[Dict[int, int]]:
        """
        Extract flag combinations from flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dictionary of flag combinations and their counts, or None if not available
            
        Raises:
            FlagAnalysisError: If flag combination extraction fails
        """
        try:
            # Check if we have packet data with flags
            if "packets" not in flow_data or not flow_data["packets"]:
                return None
            
            # Extract flags from packets
            flag_combinations = Counter()
            for packet in flow_data["packets"]:
                if "flags" in packet:
                    flags = packet["flags"]
                    flag_combinations[flags] += 1
            
            return flag_combinations
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "extract_flag_combinations", "error", "errors")
            return None
    
    def _extract_flag_sequence(self, flow_data: Dict[str, Any]) -> Optional[List[int]]:
        """
        Extract flag sequence from flow data.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            List of flags in sequence, or None if not available
            
        Raises:
            FlagAnalysisError: If flag sequence extraction fails
        """
        try:
            # Check if we have packet data with flags
            if "packets" not in flow_data or not flow_data["packets"]:
                return None
            
            # Extract flags in sequence
            flag_sequence = []
            for packet in flow_data["packets"]:
                if "flags" in packet:
                    flags = packet["flags"]
                    flag_sequence.append(flags)
            
            return flag_sequence
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "extract_flag_sequence", "error", "errors")
            return None
    
    def _has_3way_handshake(self, flag_sequence: List[int]) -> bool:
        """
        Check if sequence contains a 3-way handshake.
        
        Args:
            flag_sequence: List of flags in sequence
            
        Returns:
            True if 3-way handshake detected, False otherwise
            
        Raises:
            FlagAnalysisError: If handshake detection fails
        """
        try:
            if len(flag_sequence) < 3:
                return False
            
            # Look for SYN -> SYN-ACK -> ACK pattern
            for i in range(len(flag_sequence) - 2):
                if (flag_sequence[i] == self.TCP_SYN and
                    flag_sequence[i+1] == (self.TCP_SYN | self.TCP_ACK) and
                    flag_sequence[i+2] == self.TCP_ACK):
                    return True
            
            return False
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "has_3way_handshake", "error", "errors")
            return False
    
    def _has_complete_teardown(self, flag_sequence: List[int]) -> bool:
        """
        Check if sequence contains a complete connection teardown.
        
        Args:
            flag_sequence: List of flags in sequence
            
        Returns:
            True if complete teardown detected, False otherwise
            
        Raises:
            FlagAnalysisError: If teardown detection fails
        """
        try:
            if len(flag_sequence) < 4:
                return False
            
            # Look for FIN-ACK -> ACK -> FIN-ACK -> ACK pattern
            fin_ack_count = 0
            ack_count = 0
            
            for flags in flag_sequence:
                if flags == (self.TCP_FIN | self.TCP_ACK):
                    fin_ack_count += 1
                elif flags == self.TCP_ACK:
                    ack_count += 1
            
            return fin_ack_count >= 2 and ack_count >= 2
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "has_complete_teardown", "error", "errors")
            return False
    
    def _calculate_sequence_complexity(self, flag_sequence: List[int]) -> float:
        """
        Calculate complexity of flag sequence.
        
        Args:
            flag_sequence: List of flags in sequence
            
        Returns:
            Complexity score (0-1)
            
        Raises:
            FlagAnalysisError: If complexity calculation fails
        """
        try:
            if len(flag_sequence) < 2:
                return 0.0
            
            # Count unique flag combinations
            unique_combinations = set()
            for i in range(len(flag_sequence) - 1):
                unique_combinations.add((flag_sequence[i], flag_sequence[i+1]))
            
            # Calculate complexity as ratio of unique combinations to possible combinations
            max_unique = min(len(flag_sequence) - 1, self.max_combinations)
            if max_unique == 0:
                return 0.0
            
            return len(unique_combinations) / max_unique
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "calculate_sequence_complexity", "error", "errors")
            return 0.0
    
    def _has_abnormal_sequence(self, flag_sequence: List[int]) -> bool:
        """
        Check if sequence contains abnormal flag patterns.
        
        Args:
            flag_sequence: List of flags in sequence
            
        Returns:
            True if abnormal patterns detected, False otherwise
            
        Raises:
            FlagAnalysisError: If abnormal pattern detection fails
        """
        try:
            if len(flag_sequence) < 2:
                return False
            
            # Check for common abnormal patterns
            for i in range(len(flag_sequence) - 1):
                # Multiple SYN flags without ACK
                if (flag_sequence[i] == self.TCP_SYN and
                    flag_sequence[i+1] == self.TCP_SYN):
                    return True
                
                # RST after SYN-ACK
                if (flag_sequence[i] == (self.TCP_SYN | self.TCP_ACK) and
                    flag_sequence[i+1] == self.TCP_RST):
                    return True
                
                # Multiple FIN flags without ACK
                if (flag_sequence[i] == self.TCP_FIN and
                    flag_sequence[i+1] == self.TCP_FIN):
                    return True
            
            return False
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "has_abnormal_sequence", "error", "errors")
            return False
    
    def _most_common_subsequence(self, flag_sequence: List[int]) -> int:
        """
        Find the most common flag subsequence.
        
        Args:
            flag_sequence: List of flags in sequence
            
        Returns:
            Most common subsequence length
            
        Raises:
            FlagAnalysisError: If subsequence analysis fails
        """
        try:
            if len(flag_sequence) < 2:
                return 0
            
            # Count occurrences of each subsequence
            subsequence_counts = Counter()
            for i in range(len(flag_sequence) - 1):
                subsequence = tuple(flag_sequence[i:i+2])
                subsequence_counts[subsequence] += 1
            
            # Find most common subsequence
            if subsequence_counts:
                return max(subsequence_counts.values())
            else:
                return 0
            
        except Exception as e:
            self._update_stats("computation_errors")
            self._handle_error(e, "most_common_subsequence", "error", "errors")
            return 0
    
    def extract_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract flag analysis features from a flow.
        
        Args:
            flow_data: Flow data dictionary
            
        Returns:
            Dictionary of extracted features
            
        Raises:
            FlagAnalysisError: If feature extraction fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                return {}
            
            features = {}
            
            # Extract basic flag counts
            try:
                flag_combinations = self._extract_flag_combinations(flow_data)
                if flag_combinations:
                    # Count individual flags
                    for flag, name in self.FLAG_NAMES.items():
                        count = sum(1 for flags in flag_combinations if flags & flag)
                        features[f"flag_{name.lower()}_count"] = count
                    
                    # Count common combinations
                    for flags, name in self.COMMON_COMBINATIONS.items():
                        count = flag_combinations.get(flags, 0)
                        features[f"flag_{name.lower()}_count"] = count
            except Exception as e:
                self._update_stats("computation_errors")
                raise FlagAnalysisError(f"Failed to extract basic flag counts: {str(e)}")
            
            # Extract flag sequence features if enabled
            if self.analyze_sequences:
                try:
                    flag_sequence = self._extract_flag_sequence(flow_data)
                    if flag_sequence:
                        # Check for 3-way handshake
                        features["has_3way_handshake"] = self._has_3way_handshake(flag_sequence)
                        
                        # Check for complete teardown
                        features["has_complete_teardown"] = self._has_complete_teardown(flag_sequence)
                        
                        # Calculate sequence complexity
                        features["sequence_complexity"] = self._calculate_sequence_complexity(flag_sequence)
                        
                        # Check for abnormal patterns
                        features["has_abnormal_sequence"] = self._has_abnormal_sequence(flag_sequence)
                        
                        # Find most common subsequence
                        features["most_common_subsequence_count"] = self._most_common_subsequence(flag_sequence)
                except Exception as e:
                    self._update_stats("computation_errors")
                    raise FlagAnalysisError(f"Failed to extract flag sequence features: {str(e)}")
            
            # Update statistics
            self._update_stats("features_extracted")
            return features
            
        except Exception as e:
            self._handle_error(e, "extract_features", "error", "errors")
            raise FlagAnalysisError(f"Feature extraction failed: {str(e)}")
