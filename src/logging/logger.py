"""
Logging module for the Network Feature Extractor.
Provides structured JSON logging with file rotation.
"""

import os
import json
import logging
from logging.handlers import RotatingFileHandler
import structlog
from typing import Dict, Any, Optional

# Log levels mapping
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}


class Logger:
    """Logger manager for the Network Feature Extractor."""
    
    def __init__(self, config):
        """
        Initialize the logger.
        
        Args:
            config: Configuration object containing logging settings
        """
        self.config = config
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> structlog.stdlib.BoundLogger:
        """
        Set up the logger based on configuration.
        
        Returns:
            Configured logger instance
        """
        # Get logging configuration
        log_format = self.config.get('logging', 'format', 'json')
        log_level_str = self.config.get('logging', 'level', 'info')
        log_file = self.config.get('logging', 'file', './logs/netflow.log')
        max_size_mb = self.config.get('logging', 'max_size_mb', 100)
        backup_count = self.config.get('logging', 'backup_count', 5)
        
        # Convert log level string to constant
        log_level = LOG_LEVELS.get(log_level_str.lower(), logging.INFO)
        
        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Set up standard logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear any existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count
        )
        file_handler.setLevel(log_level)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Set up structlog processors based on format
        if log_format.lower() == 'json':
            structlog_processors = [
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ]
            
            # JSON formatter for standard logging
            class JsonFormatter(logging.Formatter):
                def format(self, record):
                    log_record = {
                        'timestamp': self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
                        'level': record.levelname,
                        'logger': record.name,
                        'message': record.getMessage()
                    }
                    if record.exc_info:
                        log_record['exception'] = self.formatException(record.exc_info)
                    return json.dumps(log_record)
            
            formatter = JsonFormatter()
            
        else:  # Text format
            structlog_processors = [
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.dev.ConsoleRenderer()
            ]
            
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        
        # Apply formatter to handlers
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to root logger
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        # Configure structlog
        structlog.configure(
            processors=structlog_processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Return a logger instance for the application
        return structlog.get_logger("network-feature-extractor")
    
    def get_logger(self, component: Optional[str] = None) -> structlog.stdlib.BoundLogger:
        """
        Get a logger for a specific component.
        
        Args:
            component: Component name
            
        Returns:
            Logger instance bound with component context
        """
        if component:
            # Get component-specific log level
            log_level_str = self.config.get_log_level(component)
            log_level = LOG_LEVELS.get(log_level_str.lower(), logging.INFO)
            
            # Create a component-specific logger with the same handlers
            logger = self.logger.bind(component=component)
            
            # Set the component level (affects only structlog's filter_by_level processor)
            logger = logger.new(level=log_level)
            
            return logger
        
        return self.logger
    
    def update_log_level(self, component: Optional[str] = None) -> None:
        """
        Update the log level for a component based on configuration.
        
        Args:
            component: Component name
        """
        # This could be used to dynamically update log levels at runtime
        log_level_str = self.config.get_log_level(component)
        log_level = LOG_LEVELS.get(log_level_str.lower(), logging.INFO)
        
        if component:
            # Get the logger for the specific component
            logging.getLogger(f"network-feature-extractor.{component}").setLevel(log_level)
        else:
            # Update the root logger level
            logging.getLogger().setLevel(log_level)
