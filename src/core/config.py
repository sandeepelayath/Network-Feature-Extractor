"""
Configuration module for the Network Feature Extractor.
Handles loading and validation of configuration from YAML files with enhanced error handling and type safety.
"""

import os
import yaml
import threading
import copy
from typing import Dict, Any, Optional, TypeVar, Generic, Type
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from contextlib import contextmanager
import time

T = TypeVar('T')

class ConfigError(Exception):
    """Base exception for configuration errors."""
    pass

class ConfigInitializationError(ConfigError):
    """Exception raised during configuration initialization."""
    pass

class ConfigValidationError(ConfigError):
    """Exception raised when configuration validation fails."""
    pass

class ConfigSectionError(ConfigError):
    """Exception raised when a configuration section is invalid."""
    pass

class ConfigValueError(ConfigError):
    """Exception raised when a configuration value is invalid."""
    pass

class ConfigIOError(ConfigError):
    """Exception raised during configuration I/O operations."""
    pass

class ConfigStateError(ConfigError):
    """Exception raised during configuration state management."""
    pass

class ConfigType(Enum):
    """Enum for configuration value types."""
    STRING = 'string'
    INTEGER = 'integer'
    FLOAT = 'float'
    BOOLEAN = 'boolean'
    LIST = 'list'
    DICT = 'dict'

@dataclass
class ConfigValue:
    """Configuration value with type and validation."""
    value: Any
    type: ConfigType
    required: bool = True
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    choices: Optional[list] = None
    default: Any = None

@dataclass
class ConfigSection:
    """Configuration section with validation rules."""
    name: str
    required: bool = True
    values: Dict[str, ConfigValue] = field(default_factory=dict)

class Config:
    """Enhanced configuration manager for the Network Feature Extractor."""
    
    DEFAULT_CONFIG_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        'config',
        'config.yaml'
    )
    
    # Configuration schema
    CONFIG_SCHEMA = {
        'network': ConfigSection(
            'network',
            values={
                'interface': ConfigValue(
                    value=None,
                    type=ConfigType.STRING,
                    required=True
                ),
                'promiscuous': ConfigValue(
                    value=True,
                    type=ConfigType.BOOLEAN,
                    required=False
                ),
                'mode': ConfigValue(
                    value='xdp',
                    type=ConfigType.STRING,
                    required=False,
                    choices=['xdp', 'raw_socket']
                ),
                'sampling': ConfigValue(
                    value={'enabled': False, 'rate': 1.0},
                    type=ConfigType.DICT,
                    required=False
                ),
                'packet_queue_size': ConfigValue(
                    value=100000,
                    type=ConfigType.INTEGER,
                    required=False,
                    min_value=1000
                ),
                'ring_buffer_size': ConfigValue(
                    value=262144,
                    type=ConfigType.INTEGER,
                    required=False,
                    min_value=65536
                ),
                'overflow_policy': ConfigValue(
                    value='drop',
                    type=ConfigType.STRING,
                    required=False,
                    choices=['drop', 'block']
                )
            }
        ),
        'protocols': ConfigSection(
            'protocols',
            values={
                'tcp': ConfigValue(
                    value={'enabled': True, 'timeout': 300},
                    type=ConfigType.DICT,
                    required=False
                ),
                'udp': ConfigValue(
                    value={'enabled': True, 'timeout': 180},
                    type=ConfigType.DICT,
                    required=False
                ),
                'icmp': ConfigValue(
                    value={'enabled': True, 'timeout': 60},
                    type=ConfigType.DICT,
                    required=False
                ),
                'quic': ConfigValue(
                    value={'enabled': True, 'timeout': 300},
                    type=ConfigType.DICT,
                    required=False
                ),
                'sctp': ConfigValue(
                    value={'enabled': True, 'timeout': 300},
                    type=ConfigType.DICT,
                    required=False
                ),
                'dccp': ConfigValue(
                    value={'enabled': True, 'timeout': 300},
                    type=ConfigType.DICT,
                    required=False
                ),
                'rsvp': ConfigValue(
                    value={'enabled': True, 'timeout': 60},
                    type=ConfigType.DICT,
                    required=False
                ),
                'ipv4': ConfigValue(
                    value={'enabled': True},
                    type=ConfigType.DICT,
                    required=False
                ),
                'ipv6': ConfigValue(
                    value={'enabled': True},
                    type=ConfigType.DICT,
                    required=False
                )
            }
        ),
        'flow_tracker': ConfigSection(
            'flow_tracker',
            values={
                'cleanup_interval': ConfigValue(
                    value=10,
                    type=ConfigType.INTEGER,
                    required=False,
                    min_value=1
                ),
                'cleanup_threshold': ConfigValue(
                    value=10000,
                    type=ConfigType.INTEGER,
                    required=False,
                    min_value=1000
                ),
                'enable_dynamic_cleanup': ConfigValue(
                    value=True,
                    type=ConfigType.BOOLEAN,
                    required=False
                ),
                'max_flows': ConfigValue(
                    value=1000000,
                    type=ConfigType.INTEGER,
                    required=False,
                    min_value=1000
                )
            }
        ),
        'output': ConfigSection(
            'output',
            values={
                'directory': ConfigValue(
                    value='./output',
                    type=ConfigType.STRING,
                    required=True
                ),
                'filename_prefix': ConfigValue(
                    value='netflow',
                    type=ConfigType.STRING,
                    required=False
                ),
                'rotation': ConfigValue(
                    value={'size_limit_mb': 250, 'time_limit_min': 30},
                    type=ConfigType.DICT,
                    required=False
                ),
                'compression': ConfigValue(
                    value={'enabled': True, 'algorithm': 'gzip'},
                    type=ConfigType.DICT,
                    required=False
                )
            }
        )
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, uses the default path.
            
        Raises:
            ConfigInitializationError: If configuration initialization fails
        """
        try:
            self.config_path = config_path if config_path else self.DEFAULT_CONFIG_PATH
            self.config = {}
            self._config_lock = threading.RLock()
            self._cache = {}
            self.logger = logging.getLogger(__name__)
            
            # Initialize state management
            self.state_lock = threading.RLock()
            self.initialized = False
            self.last_update = 0
            
            # Statistics
            self.stats_lock = threading.RLock()
            self.stats = {
                "load_attempts": 0,
                "load_successes": 0,
                "load_failures": 0,
                "validation_errors": 0,
                "io_errors": 0,
                "state_errors": 0,
                "cache_updates": 0,
                "cache_hits": 0,
                "cache_misses": 0
            }
            
            # Initialize configuration
            try:
                self.load_config()
                self.initialized = True
                self.last_update = time.time()
                self.logger.info("Configuration initialized successfully")
            except Exception as e:
                self._update_stats("load_failures")
                raise ConfigInitializationError(f"Failed to initialize configuration: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "initialize", "error", "load_failures")
            raise ConfigInitializationError(f"Failed to initialize configuration: {str(e)}")
    
    def _validate_state(self) -> None:
        """
        Validate current state of the configuration.
        
        Raises:
            ConfigStateError: If state validation fails
        """
        try:
            with self.state_lock:
                if not self.initialized:
                    raise ConfigStateError("Configuration not initialized")
                if not self.config:
                    raise ConfigStateError("Configuration is empty")
        except Exception as e:
            self._update_stats("state_errors")
            raise ConfigStateError(f"State validation failed: {str(e)}")
    
    def _update_state(self) -> None:
        """
        Update configuration state with error handling.
        
        Raises:
            ConfigStateError: If state update fails
        """
        try:
            with self.state_lock:
                self.last_update = time.time()
        except Exception as e:
            self._update_stats("state_errors")
            raise ConfigStateError(f"Failed to update state: {str(e)}")
    
    def _update_stats(self, stat_key: str, value: int = 1) -> None:
        """
        Update statistics with error handling.
        
        Args:
            stat_key: Key of the statistic to update
            value: Value to add to the statistic
        """
        try:
            with self.stats_lock:
                if stat_key not in self.stats:
                    self.stats[stat_key] = 0
                self.stats[stat_key] += value
        except Exception as e:
            # Don't raise here as this is used in error handling
            pass
    
    def _handle_error(self, error: Exception, context: str,
                     severity: str = "error", stat_key: str = "load_failures") -> None:
        """
        Handle errors with error handling.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            severity: Error severity ('error' or 'warning')
            stat_key: Statistics key to update
        """
        try:
            # Update statistics
            self._update_stats(stat_key)
            
            # Log error
            if severity == "error":
                self.logger.error(f"Error in {context}: {str(error)}")
            else:
                self.logger.warning(f"Warning in {context}: {str(error)}")
            
        except Exception:
            # Don't raise here as this is used in error handling
            pass
    
    @contextmanager
    def _config_lock_context(self):
        """Context manager for thread-safe configuration access."""
        try:
            with self._config_lock:
                yield
        except Exception as e:
            self._handle_error(e, "config_lock", "error", "state_errors")
            raise ConfigStateError(f"Configuration lock error: {str(e)}")
    
    def load_config(self) -> None:
        """
        Load configuration from the YAML file.
        
        Raises:
            ConfigIOError: If configuration loading fails
            ConfigValidationError: If configuration validation fails
        """
        try:
            self._update_stats("load_attempts")
            
            if not os.path.exists(self.config_path):
                raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
            
            try:
                with open(self.config_path, 'r') as f:
                    config_data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                self._update_stats("io_errors")
                raise ConfigIOError(f"Error parsing configuration file: {str(e)}")
            except Exception as e:
                self._update_stats("io_errors")
                raise ConfigIOError(f"Error reading configuration file: {str(e)}")
            
            with self._config_lock_context():
                self.config = config_data
                try:
                    self.validate_config()
                    self._update_cache()
                    self._update_state()
                    self._update_stats("load_successes")
                except Exception as e:
                    self._update_stats("validation_errors")
                    raise ConfigValidationError(f"Configuration validation failed: {str(e)}")
                
        except Exception as e:
            self._handle_error(e, "load_config", "error", "load_failures")
            raise
    
    def validate_config(self) -> None:
        """
        Validate the configuration against the schema.
        
        Raises:
            ConfigValidationError: If validation fails
        """
        try:
            with self._config_lock_context():
                # Validate required sections
                for section_name, section in self.CONFIG_SCHEMA.items():
                    if section.required and section_name not in self.config:
                        raise ConfigSectionError(f"Missing required section: {section_name}")
                    
                    if section_name in self.config:
                        # Validate section values
                        for value_name, value_schema in section.values.items():
                            if value_name in self.config[section_name]:
                                self._validate_value(
                                    self.config[section_name][value_name],
                                    value_schema,
                                    f"{section_name}.{value_name}"
                                )
                            elif value_schema.required:
                                raise ConfigValueError(
                                    f"Missing required value: {section_name}.{value_name}"
                                )
                            else:
                                # Use default value if not specified
                                self.config[section_name][value_name] = value_schema.default
                
        except ConfigError:
            raise
        except Exception as e:
            self._update_stats("validation_errors")
            raise ConfigValidationError(f"Configuration validation failed: {str(e)}")
    
    def _validate_value(self, value: Any, schema: ConfigValue, path: str) -> None:
        """
        Validate a configuration value against its schema.
        
        Args:
            value: Value to validate
            schema: Value schema
            path: Configuration path for error messages
            
        Raises:
            ConfigValueError: If validation fails
        """
        try:
            # Type validation
            if schema.type == ConfigType.INTEGER:
                if not isinstance(value, int):
                    raise ConfigValueError(f"{path} must be an integer")
            elif schema.type == ConfigType.FLOAT:
                if not isinstance(value, (int, float)):
                    raise ConfigValueError(f"{path} must be a float")
            elif schema.type == ConfigType.BOOLEAN:
                if not isinstance(value, bool):
                    raise ConfigValueError(f"{path} must be a boolean")
            elif schema.type == ConfigType.STRING:
                if not isinstance(value, str):
                    raise ConfigValueError(f"{path} must be a string")
            elif schema.type == ConfigType.LIST:
                if not isinstance(value, list):
                    raise ConfigValueError(f"{path} must be a list")
            elif schema.type == ConfigType.DICT:
                if not isinstance(value, dict):
                    raise ConfigValueError(f"{path} must be a dictionary")
            
            # Range validation
            if schema.min_value is not None and value < schema.min_value:
                raise ConfigValueError(
                    f"{path} must be at least {schema.min_value}"
                )
            if schema.max_value is not None and value > schema.max_value:
                raise ConfigValueError(
                    f"{path} must be at most {schema.max_value}"
                )
            
            # Choices validation
            if schema.choices and value not in schema.choices:
                raise ConfigValueError(
                    f"{path} must be one of {schema.choices}"
                )
                
        except ConfigValueError:
            raise
        except Exception as e:
            self._update_stats("validation_errors")
            raise ConfigValueError(f"Error validating {path}: {str(e)}")
    
    def _update_cache(self) -> None:
        """
        Update the configuration cache.
        
        Raises:
            ConfigStateError: If cache update fails
        """
        try:
            with self._config_lock_context():
                # Clear existing cache
                self._cache.clear()
                
                # Cache network settings
                network = self.config.get('network', {})
                self._cache['network_interface'] = network.get('interface')
                self._cache['sampling_enabled'] = network.get('sampling', {}).get('enabled', False)
                self._cache['sampling_rate'] = network.get('sampling', {}).get('rate', 1.0)
                self._cache['packet_queue_size'] = network.get('packet_queue_size', 100000)
                
                # Cache protocol settings
                protocols = self.config.get('protocols', {})
                self._cache['protocol_enabled'] = {
                    proto: settings.get('enabled', False)
                    for proto, settings in protocols.items()
                }
                self._cache['protocol_timeout'] = {
                    proto: settings.get('timeout', 300)
                    for proto, settings in protocols.items()
                }
                
                # Cache flow tracker settings
                flow_tracker = self.config.get('flow_tracker', {})
                self._cache['cleanup_interval'] = flow_tracker.get('cleanup_interval', 10)
                self._cache['cleanup_threshold'] = flow_tracker.get('cleanup_threshold', 10000)
                self._cache['enable_dynamic_cleanup'] = flow_tracker.get('enable_dynamic_cleanup', True)
                
                # Cache output settings
                output = self.config.get('output', {})
                self._cache['output_directory'] = output.get('directory', './output')
                self._cache['filename_prefix'] = output.get('filename_prefix', 'netflow')
                
                self._update_stats("cache_updates")
                
        except Exception as e:
            self._handle_error(e, "update_cache", "error", "state_errors")
            raise ConfigStateError(f"Cache update failed: {str(e)}")
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key within the section
            default: Default value if the key doesn't exist
            
        Returns:
            Configuration value or default
            
        Raises:
            ConfigError: If the configuration is invalid
        """
        try:
            # Validate state
            self._validate_state()
            
            # Check cache first
            cache_key = f"{section}_{key}" if key else section
            if cache_key in self._cache:
                self._update_stats("cache_hits")
                return self._cache[cache_key]
            
            self._update_stats("cache_misses")
            
            with self._config_lock_context():
                if section not in self.config:
                    return default
                
                if key is None:
                    return copy.deepcopy(self.config[section])
                
                value = self.config[section].get(key, default)
                
                # Validate the value if it exists
                if value is not None and section in self.CONFIG_SCHEMA:
                    section_schema = self.CONFIG_SCHEMA[section]
                    if key in section_schema.values:
                        self._validate_value(value, section_schema.values[key], f"{section}.{key}")
                
                return value
                
        except Exception as e:
            self._handle_error(e, "get", "error", "validation_errors")
            raise ConfigError(f"Error getting configuration value: {str(e)}")
    
    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if a feature is enabled.
        
        Args:
            feature_name: Name of the feature
            
        Returns:
            True if the feature is enabled, False otherwise
        """
        try:
            return self.get('features', feature_name, {}).get('enabled', False)
        except Exception as e:
            self._handle_error(e, "is_feature_enabled", "error", "validation_errors")
            return False
    
    def is_protocol_enabled(self, protocol_name: str) -> bool:
        """
        Check if a protocol is enabled.
        
        Args:
            protocol_name: Name of the protocol
            
        Returns:
            True if the protocol is enabled, False otherwise
        """
        try:
            return self.get('protocols', protocol_name, {}).get('enabled', False)
        except Exception as e:
            self._handle_error(e, "is_protocol_enabled", "error", "validation_errors")
            return False
    
    def get_protocol_timeout(self, protocol_name: str, default: int = 300) -> int:
        """
        Get the timeout for a protocol.
        
        Args:
            protocol_name: Name of the protocol
            default: Default timeout value
            
        Returns:
            Protocol timeout in seconds
        """
        try:
            return self.get('protocols', protocol_name, {}).get('timeout', default)
        except Exception as e:
            self._handle_error(e, "get_protocol_timeout", "error", "validation_errors")
            return default
    
    def update_section(self, section: str, values: Dict[str, Any]) -> None:
        """
        Update a configuration section.
        
        Args:
            section: Section name
            values: New values for the section
            
        Raises:
            ConfigError: If the update fails
        """
        try:
            # Validate state
            self._validate_state()
            
            with self._config_lock_context():
                if section not in self.CONFIG_SCHEMA:
                    raise ConfigSectionError(f"Invalid section: {section}")
                
                # Validate new values
                section_schema = self.CONFIG_SCHEMA[section]
                for key, value in values.items():
                    if key in section_schema.values:
                        self._validate_value(value, section_schema.values[key], f"{section}.{key}")
                
                # Update section
                if section not in self.config:
                    self.config[section] = {}
                self.config[section].update(values)
                
                # Update cache and state
                self._update_cache()
                self._update_state()
                
        except Exception as e:
            self._handle_error(e, "update_section", "error", "validation_errors")
            raise ConfigError(f"Failed to update configuration section: {str(e)}")
    
    def save_config(self, config_path: Optional[str] = None) -> None:
        """
        Save the current configuration to a file.
        
        Args:
            config_path: Path to save the configuration to. If None, uses the current path.
            
        Raises:
            ConfigIOError: If saving fails
        """
        try:
            # Validate state
            self._validate_state()
            
            save_path = config_path if config_path else self.config_path
            
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                
                with open(save_path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False)
                
                self.logger.info(f"Configuration saved successfully to {save_path}")
                
            except Exception as e:
                self._update_stats("io_errors")
                raise ConfigIOError(f"Failed to save configuration: {str(e)}")
            
        except Exception as e:
            self._handle_error(e, "save_config", "error", "io_errors")
            raise ConfigIOError(f"Failed to save configuration: {str(e)}")
