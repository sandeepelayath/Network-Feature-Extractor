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
import threading
import time
from pathlib import Path


class LoggerError(Exception):
    """Base exception for logger errors."""
    pass


class LoggerInitializationError(LoggerError):
    """Exception raised during logger initialization."""
    pass


class LoggerCleanupError(LoggerError):
    """Exception raised during logger cleanup."""
    pass


class LoggerConfigError(LoggerError):
    """Exception raised during logger configuration."""
    pass


class LoggerStateError(LoggerError):
    """Exception raised during logger state management."""
    pass


class LoggerIOError(LoggerError):
    """Exception raised during logger I/O operations."""
    pass


# Log levels mapping
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}


class Logger:
    """Logger class for handling application logging."""
    
    def __init__(self, config):
        """Initialize the logger with configuration."""
        self.config = config
        self.initialized = False
        self.running = True
        self.logger = None
        self._setup_logger()
    
    def _setup_logger(self):
        """Set up the logger with handlers and formatters."""
        try:
            # Get configuration values
            log_file = self.config.get('logging', 'file')
            max_size = self.config.get('logging', 'max_size_mb', 1) * 1024 * 1024  # Convert MB to bytes
            backup_count = self.config.get('logging', 'backup_count', 3)
            
            # Create log directory if it doesn't exist
            log_dir = Path(log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Create logger
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            
            # Create formatter
            formatter = logging.Formatter(
                '{"level": "%(levelname)s", "message": "%(message)s", "timestamp": "%(asctime)s.%(msecs)03dZ"%(extra_fields)s}',
                datefmt='%Y-%m-%dT%H:%M:%S'
            )
            
            # Add file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            
            # Add console handler for initialization message only
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            
            # Log initialization message
            self.logger.info('Logger initialized successfully')
            
            # Remove console handler after initialization
            self.logger.removeHandler(console_handler)
            
            self.initialized = True
            
        except Exception as e:
            raise LoggerInitializationError(f"Failed to initialize logger: {str(e)}")
    
    def log(self, level, message, **kwargs):
        """Log a message with the specified level and additional fields."""
        if not self.initialized or not self.running:
            raise LoggerError("Logger not initialized or not running")
        
        try:
            # Get the appropriate logging method
            log_method = getattr(self.logger, level.lower())
            
            # Format extra fields for JSON output
            extra_fields = ''
            if kwargs:
                extra_fields = ', ' + ', '.join(f'"{k}": {json.dumps(v)}' for k, v in kwargs.items())
            
            # Create a custom formatter for this log entry
            formatter = logging.Formatter(
                '{"level": "%(levelname)s", "message": "%(message)s", "timestamp": "%(asctime)s.%(msecs)03dZ"' + extra_fields + '}',
                datefmt='%Y-%m-%dT%H:%M:%S'
            )
            
            # Update formatter for all handlers
            for handler in self.logger.handlers:
                handler.setFormatter(formatter)
            
            # Log the message
            log_method(message)
            
        except Exception as e:
            raise LoggerError(f"Failed to log message: {str(e)}")
    
    def cleanup(self):
        """Clean up logger resources."""
        if self.logger:
            for handler in self.logger.handlers:
                handler.close()
                self.logger.removeHandler(handler)
        self.running = False
