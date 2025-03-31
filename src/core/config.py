"""
Configuration module for the Network Feature Extractor.
Handles loading and validation of configuration from YAML files.
"""

import os
import yaml
import threading
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for the Network Feature Extractor."""
    
    DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                      'config', 'config.yaml')
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, uses the default path.
        """
        self.config_path = config_path if config_path else self.DEFAULT_CONFIG_PATH
        self.config = {}
        self._config_lock = threading.RLock()  # Reentrant lock for thread safety
        
        # Local cache for frequently accessed configuration values
        self._cache = {}
        
        # Default values for important configuration settings
        self.default_values = {
            'network': {
                'interface': 'eth0',
                'promiscuous': True,
                'mode': 'xdp',
                'sampling': {
                    'enabled': False,
                    'rate': 1.0
                },
                'packet_queue_size': 100000,
                'ring_buffer_size': 262144,
                'overflow_policy': 'drop'
            },
            'protocols': {
                'tcp': {'enabled': True, 'timeout': 300},
                'udp': {'enabled': True, 'timeout': 180},
                'icmp': {'enabled': True, 'timeout': 60},
                'quic': {'enabled': True, 'timeout': 300},
                'sctp': {'enabled': True, 'timeout': 300},
                'dccp': {'enabled': True, 'timeout': 300},
                'rsvp': {'enabled': True, 'timeout': 60},
                'ipv4': {'enabled': True},
                'ipv6': {'enabled': True}
            },
            'flow_tracker': {
                'cleanup_interval': 10,
                'cleanup_threshold': 10000,
                'enable_dynamic_cleanup': True,
                'max_flows': 1000000
            },
            'output': {
                'directory': './output',
                'filename_prefix': 'netflow',
                'rotation': {
                    'size_limit_mb': 250,
                    'time_limit_min': 30
                },
                'compression': {
                    'enabled': True,
                    'algorithm': 'gzip'
                }
            }
        }
        
        # Load the configuration
        self.load_config()
        
        # Initialize cache with commonly accessed values
        self._update_cache()
        
    def _update_cache(self) -> None:
        """Update the local cache with frequently accessed configuration values."""
        with self._config_lock:
            # Network settings
            self._cache['network_interface'] = self.config.get('network', {}).get('interface')
            self._cache['sampling_enabled'] = self.config.get('network', {}).get('sampling', {}).get('enabled', False)
            self._cache['sampling_rate'] = self.config.get('network', {}).get('sampling', {}).get('rate', 1.0)
            self._cache['packet_queue_size'] = self.config.get('network', {}).get('packet_queue_size', 100000)
            
            # Protocol settings - cache enabled status for common protocols
            protocols = ['tcp', 'udp', 'icmp', 'quic', 'sctp', 'dccp', 'rsvp', 'ipv4', 'ipv6']
            self._cache['protocol_enabled'] = {}
            self._cache['protocol_timeout'] = {}
            
            for protocol in protocols:
                self._cache['protocol_enabled'][protocol] = self.config.get('protocols', {}).get(protocol, {}).get('enabled', False)
                self._cache['protocol_timeout'][protocol] = self.config.get('protocols', {}).get(protocol, {}).get('timeout', 300)
            
            # Flow tracker settings
            self._cache['cleanup_interval'] = self.config.get('flow_tracker', {}).get('cleanup_interval', 10)
            self._cache['cleanup_threshold'] = self.config.get('flow_tracker', {}).get('cleanup_threshold', 10000)
            self._cache['enable_dynamic_cleanup'] = self.config.get('flow_tracker', {}).get('enable_dynamic_cleanup', True)
            
            # Output settings
            self._cache['output_directory'] = self.config.get('output', {}).get('directory', './output')
            self._cache['filename_prefix'] = self.config.get('output', {}).get('filename_prefix', 'netflow')
        
    def load_config(self) -> None:
        """Load configuration from the YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Acquire lock before modifying the configuration
            with self._config_lock:
                self.config = config_data
                self.validate_config()
                
                # Update the cache with new values
                self._update_cache()
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing configuration file: {e}")
    
    def validate_config(self) -> None:
        """Validate the configuration structure and values."""
        # No need for a lock here as this is called from load_config which already has the lock
        
        # Check required sections
        required_sections = ['network', 'features', 'protocols', 'output', 'monitoring', 'logging']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Validate network section
        if 'interface' not in self.config['network']:
            raise ValueError("Network interface must be specified")
        
        # Validate sampling rate if enabled
        if self.config['network'].get('sampling', {}).get('enabled', False):
            rate = self.config['network']['sampling'].get('rate', 0)
            if not 0 < rate <= 1:
                raise ValueError("Sampling rate must be between 0 and 1")
        
        # Validate output directory
        output_dir = self.config['output'].get('directory')
        if not output_dir:
            raise ValueError("Output directory must be specified")
        
        # Validate rotation settings
        size_limit = self.config['output'].get('rotation', {}).get('size_limit_mb')
        time_limit = self.config['output'].get('rotation', {}).get('time_limit_min')
        if size_limit is not None and size_limit <= 0:
            raise ValueError("Rotation size limit must be positive")
        if time_limit is not None and time_limit <= 0:
            raise ValueError("Rotation time limit must be positive")
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key within the section
            default: Default value if the key doesn't exist
            
        Returns:
            Configuration value or default
        """
        # Check cache first for common values
        cache_key = f"{section}_{key}" if key else section
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        # For protocol enabled/timeout status, check the specific cache
        if section == 'protocols' and key and key.endswith('.enabled') and key.split('.')[0] in self._cache.get('protocol_enabled', {}):
            protocol = key.split('.')[0]
            return self._cache['protocol_enabled'].get(protocol, default)
            
        if section == 'protocols' and key and key.endswith('.timeout') and key.split('.')[0] in self._cache.get('protocol_timeout', {}):
            protocol = key.split('.')[0]
            return self._cache['protocol_timeout'].get(protocol, default)
        
        # Determine the default value to use (in order of precedence):
        # 1. User-provided default in this method call
        # 2. Default from the default_values dictionary
        # 3. None
        resolved_default = default
        if resolved_default is None and section in self.default_values:
            if key is None:
                resolved_default = self.default_values[section]
            elif key in self.default_values[section]:
                resolved_default = self.default_values[section][key]
            elif '.' in key:  # Handle nested keys like 'sampling.rate'
                parts = key.split('.')
                value = self.default_values.get(section)
                for part in parts:
                    if value and isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        value = None
                        break
                resolved_default = value
        
        # Fall back to configuration lookup with lock
        with self._config_lock:
            if section not in self.config:
                return resolved_default
            
            if key is None:
                # Return a deep copy to prevent modifications
                import copy
                return copy.deepcopy(self.config[section])
            
            value = None
            if key in self.config[section]:
                # Get the value (deep copy for mutable values)
                import copy
                value = copy.deepcopy(self.config[section][key])
            else:
                value = resolved_default
            
            # Perform runtime validation for specific settings
            try:
                if section == 'network':
                    if key == 'sampling' and value:
                        # Validate sampling rate
                        rate = value.get('rate', 0)
                        if not 0 <= rate <= 1:
                            self.logger.warning(
                                "Invalid sampling rate, clamping to valid range",
                                rate=rate
                            )
                            value['rate'] = max(0, min(1, rate))
                            
                    elif key == 'packet_queue_size' and value:
                        # Ensure queue size is positive
                        if value <= 0:
                            self.logger.warning(
                                "Invalid packet_queue_size, using default",
                                value=value
                            )
                            value = 100000  # Default to a reasonable size
                            
                elif section == 'protocols' and key and value:
                    # Ensure timeout values are reasonable
                    if key.endswith('.timeout'):
                        if value <= 0:
                            self.logger.warning(
                                f"Invalid protocol timeout for {key}, using default",
                                value=value
                            )
                            value = 300  # Default timeout
            except Exception as e:
                self.logger.warning(
                    f"Error validating configuration value for {section}.{key}",
                    error=str(e)
                )
            
            return value
    
    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Check if a feature is enabled in the configuration.
        
        Args:
            feature_name: Name of the feature to check
            
        Returns:
            True if the feature is enabled, False otherwise
        """
        # Check cache
        cache_key = f"features_{feature_name}_enabled"
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        # Fall back to lock
        with self._config_lock:
            result = self.config.get('features', {}).get(feature_name, {}).get('enabled', False)
            # Update cache
            self._cache[cache_key] = result
            return result
    
    def is_protocol_enabled(self, protocol_name: str) -> bool:
        """
        Check if a protocol is enabled in the configuration.
        
        Args:
            protocol_name: Name of the protocol to check
            
        Returns:
            True if the protocol is enabled, False otherwise
        """
        # Check cache
        if protocol_name in self._cache.get('protocol_enabled', {}):
            return self._cache['protocol_enabled'][protocol_name]
            
        # Fall back to lock
        with self._config_lock:
            result = self.config.get('protocols', {}).get(protocol_name, {}).get('enabled', False)
            # Update cache
            if 'protocol_enabled' not in self._cache:
                self._cache['protocol_enabled'] = {}
            self._cache['protocol_enabled'][protocol_name] = result
            return result
    
    def get_protocol_timeout(self, protocol_name: str, default: int = 300) -> int:
        """
        Get timeout value for a specific protocol.
        
        Args:
            protocol_name: Name of the protocol (e.g., 'tcp', 'udp')
            default: Default timeout value if not found
            
        Returns:
            Timeout value in seconds
        """
        # Known protocol defaults based on common practices
        protocol_defaults = {
            'tcp': 300,    # 5 minutes
            'udp': 180,    # 3 minutes
            'icmp': 60,    # 1 minute
            'quic': 300,   # 5 minutes
            'sctp': 300,   # 5 minutes
            'dccp': 300,   # 5 minutes
            'rsvp': 60,    # 1 minute
            'unknown': default
        }
        
        # Check cache first
        if protocol_name in self._cache.get('protocol_timeout', {}):
            return self._cache['protocol_timeout'][protocol_name]
            
        # Look up in configuration with lock
        with self._config_lock:
            # Look for protocol-specific timeout in config
            timeout = self.config.get('protocols', {}).get(protocol_name, {}).get('timeout')
            
            if timeout is not None:
                # Update cache
                if 'protocol_timeout' not in self._cache:
                    self._cache['protocol_timeout'] = {}
                self._cache['protocol_timeout'][protocol_name] = timeout
                return timeout
                
            # Return known default if available, otherwise user-provided default
            return protocol_defaults.get(protocol_name, default)
    
    def get_log_level(self, component: Optional[str] = None) -> str:
        """
        Get the log level for a component.
        
        Args:
            component: Component name
            
        Returns:
            Log level string
        """
        # Check cache
        cache_key = f"log_level_{component}" if component else "log_level_default"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Fall back to lock
        with self._config_lock:
            default_level = self.config.get('logging', {}).get('level', 'info')
            if component is None:
                self._cache["log_level_default"] = default_level
                return default_level
            
            result = self.config.get('logging', {}).get('components', {}).get(component, default_level)
            self._cache[cache_key] = result
            return result
    
    def update_section(self, section: str, values: Dict[str, Any]) -> None:
        """
        Update a section of the configuration.
        
        Args:
            section: Section name
            values: Dictionary of values to update
        """
        with self._config_lock:
            if section not in self.config:
                self.config[section] = {}
                
            # Update the section with new values
            for key, value in values.items():
                self.config[section][key] = value
                
            # Update cache after modification
            self._update_cache()
    
    def save_config(self, config_path: Optional[str] = None) -> None:
        """
        Save the current configuration to a file.
        
        Args:
            config_path: Path to save the configuration file. If None, uses the current path.
        """
        path = config_path if config_path else self.config_path
        
        with self._config_lock:
            try:
                with open(path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False)
            except Exception as e:
                raise IOError(f"Failed to save configuration: {e}")
