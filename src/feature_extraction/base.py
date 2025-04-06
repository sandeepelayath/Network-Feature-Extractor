"""
Base Feature Extractor module for the Network Feature Extractor.
Provides a base class for all feature extractors with enhanced error handling and performance monitoring.
"""

import abc
from typing import Dict, Any, List, Optional, Set
from structlog import get_logger
from dataclasses import dataclass
from enum import Enum, auto
import threading
import time
from datetime import datetime

from ..core.config import Config
from ..logging.logger import Logger


class FeatureError(Exception):
    """Base exception for feature extractor errors."""
    pass


class FeatureInitializationError(FeatureError):
    """Exception raised during feature extractor initialization."""
    pass


class FeatureCleanupError(FeatureError):
    """Exception raised during feature extractor cleanup."""
    pass


class FeatureStatsError(FeatureError):
    """Exception raised during statistics management."""
    pass


class FeatureConfigError(FeatureError):
    """Exception raised during configuration validation."""
    pass


class FeatureStateError(FeatureError):
    """Exception raised during state management."""
    pass


class FeatureDependencyError(FeatureError):
    """Exception raised when dependencies are missing."""
    pass


class FeatureIOError(FeatureError):
    """Exception raised during I/O operations."""
    pass


class FeatureResourceError(FeatureError):
    """Exception raised when resource limits are exceeded."""
    pass


class FeatureTimeoutError(FeatureError):
    """Exception raised when operations timeout."""
    pass


class FeatureType(Enum):
    """Types of features that can be extracted."""
    BASIC = auto()
    STATISTICAL = auto()
    TEMPORAL = auto()
    BEHAVIORAL = auto()
    PROTOCOL = auto()
    SECURITY = auto()


@dataclass
class FeatureMetadata:
    """Metadata for a feature."""
    name: str
    description: str
    type: FeatureType
    version: str
    dependencies: Set[str]
    required_config: List[str]


class BaseFeatureExtractor(abc.ABC):
    """
    Base class for all feature extractors.
    Provides common functionality and defines the interface.
    
    Feature extractors are responsible for analyzing flow data and
    extracting specific features that can be used for network traffic analysis.
    """
    
    def __init__(self, config: Config, logger_manager: Logger, feature_name: str):
        """
        Initialize the feature extractor.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            feature_name: Name of the feature extractor
            
        Raises:
            FeatureInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger_manager.get_logger()
            self.feature_name = feature_name
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.running = False
            self.initialized = False
            self._is_shutting_down = False
            
            # Initialize metadata
            try:
                self.metadata = self._get_metadata()
            except Exception as e:
                raise FeatureInitializationError(f"Failed to get metadata: {str(e)}")
            
            # Check if this feature is enabled in the configuration
            try:
                self.enabled = self._is_enabled()
            except Exception as e:
                self.logger.warning(
                    "Error checking if feature is enabled, defaulting to disabled",
                    extractor=self.feature_name,
                    error=str(e)
                )
                self.enabled = False
            
            # Initialize feature-specific configuration
            try:
                self.feature_config = self._get_feature_config()
            except Exception as e:
                self.logger.warning(
                    "Error getting feature configuration, using empty configuration",
                    extractor=self.feature_name,
                    error=str(e)
                )
                self.feature_config = {}
            
            # Validate configuration
            try:
                self._validate_config()
            except Exception as e:
                raise FeatureConfigError(f"Configuration validation failed: {str(e)}")
            
            # Check dependencies
            try:
                self._check_dependencies()
            except Exception as e:
                raise FeatureDependencyError(f"Dependency check failed: {str(e)}")
            
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
                "io_errors": 0,
                "resource_errors": 0,
                "timeout_errors": 0
            }
            self.error_history: List[Dict[str, Any]] = []
            
            self.logger.info(
                f"Feature extractor initialized", 
                extractor=self.feature_name,
                version=self.metadata.version,
                enabled=self.enabled
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize feature extractor: {str(e)}"
            self.logger.error(error_msg)
            raise FeatureInitializationError(error_msg) from e
    
    def _validate_state(self) -> None:
        """
        Validate current state of the extractor.
        
        Raises:
            FeatureStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if self.running and not self.initialized:
                    raise FeatureStateError("Running state but not initialized")
                if not self.running and self.initialized:
                    raise FeatureStateError("Not running but initialized")
                if self._is_shutting_down and self.running:
                    raise FeatureStateError("Shutting down but still running")
        except Exception as e:
            raise FeatureStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """
        Update extractor state with error handling.
        
        Args:
            new_state: New state to set
            
        Raises:
            FeatureStateError: If state update fails
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
            raise FeatureStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
            
        Raises:
            FeatureStatsError: If statistics update fails
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            raise FeatureStatsError(f"Failed to update statistics: {str(e)}")
    
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
            FeatureError: If error handling fails
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
            raise FeatureError(f"Error handling failed: {str(e)}") from e
    
    def initialize(self) -> bool:
        """
        Perform any one-time initialization needed for the feature extractor.
        
        Returns:
            True if initialization successful, False otherwise
            
        Raises:
            FeatureInitializationError: If initialization fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.initialized:
                self.logger.warning("Feature extractor already initialized")
                return True
            
            # Perform initialization
            try:
                success = self._initialize()
                if success:
                    self.initialized = True
                    self._update_state(True)
                    self.logger.info("Feature extractor initialized successfully")
                    return True
                else:
                    self._update_stats("initialization_errors")
                    self.logger.error("Feature extractor initialization failed")
                    return False
            except Exception as e:
                self._update_stats("initialization_errors")
                raise FeatureInitializationError(f"Initialization failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "initialize", "error", "initialization_errors")
            return False
    
    def cleanup(self) -> None:
        """
        Cleanup resources used by the feature extractor.
        
        Raises:
            FeatureCleanupError: If cleanup fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.initialized:
                self.logger.warning("Feature extractor not initialized")
                return
            
            # Update state first
            self._update_state(False)
            self._is_shutting_down = True
            
            # Perform cleanup
            try:
                self._cleanup()
                self.initialized = False
                self.logger.info("Feature extractor cleaned up successfully")
            except Exception as e:
                self._update_stats("cleanup_errors")
                raise FeatureCleanupError(f"Cleanup failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "cleanup", "error", "cleanup_errors")
            raise FeatureCleanupError(f"Cleanup failed: {str(e)}")
    
    def update_flow(self, flow_key: Dict[str, Any], packet: Dict[str, Any]) -> None:
        """
        Update flow data with a new packet.
        
        Args:
            flow_key: Flow key dictionary
            packet: Packet data dictionary
            
        Raises:
            FeatureError: If flow update fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                return
            
            # Update flow
            try:
                self._update_flow(flow_key, packet)
                self._update_stats("flows_processed")
            except Exception as e:
                self._update_stats("errors")
                raise FeatureError(f"Flow update failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "update_flow", "error", "errors")
            raise FeatureError(f"Flow update failed: {str(e)}")
    
    def process_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process extracted features.
        
        Args:
            features: Dictionary of features to process
            
        Returns:
            Processed features dictionary
            
        Raises:
            FeatureError: If feature processing fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                return {}
            
            # Process features
            try:
                processed_features = self._process_features(features)
                self._update_stats("features_extracted")
                return processed_features
            except Exception as e:
                self._update_stats("errors")
                raise FeatureError(f"Feature processing failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "process_features", "error", "errors")
            raise FeatureError(f"Feature processing failed: {str(e)}")
    
    @abc.abstractmethod
    def _get_metadata(self) -> FeatureMetadata:
        """
        Get metadata for this feature extractor.
        This method must be implemented by all feature extractors.
        
        Returns:
            FeatureMetadata object
        """
        pass
    
    @abc.abstractmethod
    def _initialize(self) -> bool:
        """
        Perform feature-specific initialization.
        This method must be implemented by all feature extractors.
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def _cleanup(self) -> None:
        """
        Perform feature-specific cleanup.
        This method must be implemented by all feature extractors.
        """
        pass
    
    @abc.abstractmethod
    def _update_flow(self, flow_key: Dict[str, Any], packet: Dict[str, Any]) -> None:
        """
        Update flow data with a new packet.
        This method must be implemented by all feature extractors.
        
        Args:
            flow_key: Flow key dictionary
            packet: Packet data dictionary
        """
        pass
    
    @abc.abstractmethod
    def _process_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process extracted features.
        This method must be implemented by all feature extractors.
        
        Args:
            features: Dictionary of features to process
            
        Returns:
            Processed features dictionary
        """
        pass


class FeatureExtractorRegistry:
    """
    Registry for feature extractors.
    Manages the lifecycle of feature extractors and provides access to them.
    """
    
    _instance = None
    _lock = threading.RLock()
    
    @classmethod
    def get_instance(cls, config: Config = None, logger_manager: Logger = None) -> 'FeatureExtractorRegistry':
        """
        Get the singleton instance of the registry.
        
        Args:
            config: Configuration object
            logger_manager: Logger manager
            
        Returns:
            FeatureExtractorRegistry instance
            
        Raises:
            FeatureInitializationError: If initialization fails
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    if config is None or logger_manager is None:
                        raise FeatureInitializationError(
                            "Config and logger_manager required for first instance"
                        )
                    cls._instance = cls(config, logger_manager)
        return cls._instance
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the registry.
        
        Args:
            config: Configuration object
            logger_manager: Logger manager
            
        Raises:
            FeatureInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger_manager.get_logger()
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.initialized = False
            self._is_shutting_down = False
            
            # Initialize extractors
            self.extractors: Dict[str, BaseFeatureExtractor] = {}
            self.extractor_lock = threading.RLock()
            
            # Statistics
            self.stats_lock = threading.RLock()
            self.stats = {
                "total_extractors": 0,
                "enabled_extractors": 0,
                "initialization_errors": 0,
                "cleanup_errors": 0,
                "registration_errors": 0,
                "io_errors": 0,
                "resource_errors": 0,
                "timeout_errors": 0
            }
            self.error_history: List[Dict[str, Any]] = []
            
            self.logger.info("Feature extractor registry initialized")
            
        except Exception as e:
            error_msg = f"Failed to initialize registry: {str(e)}"
            self.logger.error(error_msg)
            raise FeatureInitializationError(error_msg) from e
    
    def _validate_state(self) -> None:
        """
        Validate current state of the registry.
        
        Raises:
            FeatureStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if not self.initialized:
                    raise FeatureStateError("Registry not initialized")
                if self._is_shutting_down and self.initialized:
                    raise FeatureStateError("Shutting down but still initialized")
        except Exception as e:
            raise FeatureStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self, new_state: bool) -> None:
        """
        Update registry state with error handling.
        
        Args:
            new_state: New state to set
            
        Raises:
            FeatureStateError: If state update fails
        """
        try:
            with self.state_lock:
                old_state = self.initialized
                self.initialized = new_state
                
                if old_state != new_state:
                    self.logger.info(
                        "Registry state changed",
                        old_state=old_state,
                        new_state=new_state
                    )
        except Exception as e:
            raise FeatureStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
            
        Raises:
            FeatureStatsError: If statistics update fails
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            raise FeatureStatsError(f"Failed to update statistics: {str(e)}")
    
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
            FeatureError: If error handling fails
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
                error=str(error),
                error_type=type(error).__name__,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            raise FeatureError(f"Error handling failed: {str(e)}") from e
    
    def register_extractor(self, extractor: BaseFeatureExtractor) -> None:
        """
        Register a feature extractor.
        
        Args:
            extractor: Feature extractor to register
            
        Raises:
            FeatureError: If registration fails
        """
        try:
            # Validate state
            self._validate_state()
            
            # Register extractor
            try:
                with self.extractor_lock:
                    if extractor.get_feature_name() in self.extractors:
                        self.logger.warning(
                            "Feature extractor already registered",
                            extractor=extractor.get_feature_name()
                        )
                        return
                    
                    self.extractors[extractor.get_feature_name()] = extractor
                    self._update_stats("total_extractors")
                    
                    if extractor.is_enabled():
                        self._update_stats("enabled_extractors")
                    
                    self.logger.info(
                        "Feature extractor registered",
                        extractor=extractor.get_feature_name(),
                        enabled=extractor.is_enabled()
                    )
            except Exception as e:
                self._update_stats("registration_errors")
                raise FeatureError(f"Extractor registration failed: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "register_extractor", "error", "registration_errors")
            raise FeatureError(f"Extractor registration failed: {str(e)}")
    
    def get_extractor(self, name: str) -> Optional[BaseFeatureExtractor]:
        """
        Get a feature extractor by name.
        
        Args:
            name: Name of the feature extractor
            
        Returns:
            Feature extractor if found, None otherwise
            
        Raises:
            FeatureError: If retrieval fails
        """
        try:
            with self.extractor_lock:
                return self.extractors.get(name)
        except Exception as e:
            self._handle_error(e, "get_extractor", "error", "errors")
            return None
    
    def get_all_extractors(self) -> List[BaseFeatureExtractor]:
        """
        Get all registered feature extractors.
        
        Returns:
            List of feature extractors
            
        Raises:
            FeatureError: If retrieval fails
        """
        try:
            with self.extractor_lock:
                return list(self.extractors.values())
        except Exception as e:
            self._handle_error(e, "get_all_extractors", "error", "errors")
            return []
    
    def get_enabled_extractors(self) -> List[BaseFeatureExtractor]:
        """
        Get all enabled feature extractors.
        
        Returns:
            List of enabled feature extractors
            
        Raises:
            FeatureError: If retrieval fails
        """
        try:
            with self.extractor_lock:
                return [
                    extractor for extractor in self.extractors.values()
                    if extractor.is_enabled()
                ]
        except Exception as e:
            self._handle_error(e, "get_enabled_extractors", "error", "errors")
            return []
    
    def initialize_all(self) -> bool:
        """
        Initialize all registered feature extractors.
        
        Returns:
            True if all extractors initialized successfully, False otherwise
            
        Raises:
            FeatureInitializationError: If initialization fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.initialized:
                self.logger.warning("Registry already initialized")
                return True
            
            # Initialize extractors
            success = True
            with self.extractor_lock:
                for extractor in self.extractors.values():
                    try:
                        if not extractor.initialize():
                            success = False
                            self._update_stats("initialization_errors")
                    except Exception as e:
                        success = False
                        self._update_stats("initialization_errors")
                        self._handle_error(e, "initialize_all", "error", "initialization_errors")
            
            if success:
                self._update_state(True)
                self.logger.info("All feature extractors initialized successfully")
            else:
                self.logger.error("Some feature extractors failed to initialize")
            
            return success
            
        except Exception as e:
            self._handle_error(e, "initialize_all", "error", "initialization_errors")
            return False
    
    def cleanup_all(self) -> None:
        """
        Cleanup all registered feature extractors.
        
        Raises:
            FeatureCleanupError: If cleanup fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.initialized:
                self.logger.warning("Registry not initialized")
                return
            
            # Update state first
            self._update_state(False)
            self._is_shutting_down = True
            
            # Cleanup extractors
            with self.extractor_lock:
                for extractor in self.extractors.values():
                    try:
                        extractor.cleanup()
                    except Exception as e:
                        self._update_stats("cleanup_errors")
                        self._handle_error(e, "cleanup_all", "error", "cleanup_errors")
            
            self.logger.info("All feature extractors cleaned up")
            
        except Exception as e:
            self._handle_error(e, "cleanup_all", "error", "cleanup_errors")
            raise FeatureCleanupError(f"Cleanup failed: {str(e)}")
