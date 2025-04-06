"""
CSV Writer module for the Network Feature Extractor.
Handles the generation of CSV files with flow metrics.
"""

import os
import csv
import threading
import time
import queue
import gzip
import shutil
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import logging

# Import local modules
from ..core.config import Config
from ..logging.logger import Logger

class CSVError(Exception):
    """Base exception for CSV writer errors."""
    pass

class CSVInitializationError(CSVError):
    """Exception raised during CSV writer initialization."""
    pass

class CSVCleanupError(CSVError):
    """Exception raised during CSV writer cleanup."""
    pass

class CSVWriteError(CSVError):
    """Exception raised during file writing."""
    pass

class CSVConfigError(CSVError):
    """Exception raised during configuration validation."""
    pass

class CSVStateError(CSVError):
    """Exception raised during state management."""
    pass

class CSVIOError(CSVError):
    """Exception raised during I/O operations."""
    pass

class CSVResourceError(CSVError):
    """Exception raised when resource limits are exceeded."""
    pass

class CSVTimeoutError(CSVError):
    """Exception raised when operations timeout."""
    pass

class CSVWriter:
    """CSV Writer for outputting flow metrics."""
    
    def __init__(self, config: Config, logger: Logger):
        """
        Initialize the CSV Writer.
        
        Args:
            config: Configuration object
            logger: Logger instance
            
        Raises:
            CSVInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger.get_logger("output")
            
            # Validate configuration
            self._validate_config()
            
            # Get output configuration
            output_dir = self.config.get('output', 'directory', './output')
            self.filename_prefix = self.config.get('output', 'filename_prefix', 'netflow')
            self.size_limit_mb = self.config.get('output', 'rotation', {}).get('size_limit_mb', 250)
            self.time_limit_min = self.config.get('output', 'rotation', {}).get('time_limit_min', 30)
            
            # Create output directory
            try:
                os.makedirs(output_dir, exist_ok=True)
                self.output_dir = os.path.abspath(output_dir)
            except Exception as e:
                raise CSVInitializationError(f"Failed to create output directory: {str(e)}")
            
            # CSV file and writer
            self.file = None
            self.writer = None
            self.file_lock = threading.RLock()
            
            # Column ordering and formatting
            self.columns = []
            self.column_types = {}
            
            # File rotation
            self.current_filename = ""
            self.file_start_time = 0
            self.bytes_written = 0
            self.rotation_thread = None
            self.running = False
            self.state_lock = threading.RLock()
            self._is_initialized = False
            self._is_shutting_down = False
            
            # Write queue for asynchronous writing
            self.write_queue = queue.Queue(maxsize=10000)
            self.writer_thread = None
            self.queue_lock = threading.RLock()
            
            # Error tracking
            self.consecutive_write_errors = 0
            self.max_consecutive_errors = 10
            self.error_window_seconds = 60
            self.last_error_time = 0
            
            # Initialize statistics
            self.stats = {
                "startup_errors": 0,
                "fatal_errors": 0,
                "processing_errors": 0,
                "write_errors": 0,
                "resource_errors": 0,
                "timeout_errors": 0,
                "io_errors": 0,
                "total_errors": 0,
                "last_error_time": 0,
                "error_history": []
            }
            
            # Initialize state
            self._initialize_state()
            
            self.logger.info(
                "CSV writer initialized",
                output_dir=self.output_dir,
                filename_prefix=self.filename_prefix
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize CSV writer: {str(e)}"
            self.logger.error(error_msg)
            raise CSVInitializationError(error_msg) from e
    
    def _validate_config(self) -> None:
        """Validate CSV writer configuration."""
        try:
            # Validate output directory
            output_dir = self.config.get('output', 'directory', './output')
            if not isinstance(output_dir, str):
                raise CSVConfigError("Output directory must be a string")
            
            # Validate filename prefix
            filename_prefix = self.config.get('output', 'filename_prefix', 'netflow')
            if not isinstance(filename_prefix, str):
                raise CSVConfigError("Filename prefix must be a string")
            
            # Validate size limit
            size_limit = self.config.get('output', 'rotation', {}).get('size_limit_mb', 250)
            if not isinstance(size_limit, (int, float)) or size_limit <= 0:
                raise CSVConfigError("Size limit must be a positive number")
            
            # Validate time limit
            time_limit = self.config.get('output', 'rotation', {}).get('time_limit_min', 30)
            if not isinstance(time_limit, (int, float)) or time_limit < 0:
                raise CSVConfigError("Time limit must be a non-negative number")
            
        except Exception as e:
            raise CSVConfigError(f"Configuration validation failed: {str(e)}") from e
    
    def _initialize_state(self) -> None:
        """Initialize writer state."""
        try:
            with self.state_lock:
                if self._is_initialized:
                    raise CSVStateError("Writer already initialized")
                
                self._is_initialized = True
                self._is_shutting_down = False
                self.running = False
                self.file_start_time = time.time()
                self.bytes_written = 0
                
                # Initialize statistics
                self.stats = {
                    "startup_errors": 0,
                    "fatal_errors": 0,
                    "processing_errors": 0,
                    "write_errors": 0,
                    "resource_errors": 0,
                    "timeout_errors": 0,
                    "io_errors": 0,
                    "total_errors": 0,
                    "last_error_time": 0,
                    "error_history": []
                }
                
        except Exception as e:
            raise CSVStateError(f"State initialization failed: {str(e)}") from e
    
    def _validate_state(self) -> None:
        """Validate current state of the writer."""
        try:
            with self.state_lock:
                if self.running and not self.writer_thread:
                    raise CSVStateError("Running state but no writer thread")
                if self.file and not self.writer:
                    raise CSVStateError("File open but no writer")
                if self.writer and not self.file:
                    raise CSVStateError("Writer exists but no file")
                if self._is_shutting_down and self.running:
                    raise CSVStateError("Shutting down but still running")
        except Exception as e:
            raise CSVStateError(f"State validation failed: {str(e)}") from e
    
    def _update_state(self, new_state: bool) -> None:
        """Update writer state with error handling."""
        try:
            with self.state_lock:
                old_state = self.running
                self.running = new_state
                
                if old_state != new_state:
                    self.logger.info(
                        "Writer state changed",
                        old_state=old_state,
                        new_state=new_state
                    )
        except Exception as e:
            raise CSVStateError(f"Failed to update state: {str(e)}") from e
    
    def _cleanup_resources(self) -> None:
        """Cleanup resources with error handling."""
        try:
            # Close file
            if self.file:
                try:
                    self.file.close()
                    self.file = None
                    self.writer = None
                except Exception as e:
                    self._handle_error(e, "file close", "error", "io_errors")
            
            # Stop writer thread
            if self.writer_thread and self.writer_thread.is_alive():
                try:
                    self.writer_thread.join(timeout=5.0)
                    if self.writer_thread.is_alive():
                        self.logger.warning("Writer thread did not terminate cleanly")
                except Exception as e:
                    self._handle_error(e, "writer thread cleanup", "error", "fatal_errors")
            
            # Stop rotation thread
            if self.rotation_thread and self.rotation_thread.is_alive():
                try:
                    self.rotation_thread.join(timeout=5.0)
                    if self.rotation_thread.is_alive():
                        self.logger.warning("Rotation thread did not terminate cleanly")
                except Exception as e:
                    self._handle_error(e, "rotation thread cleanup", "error", "fatal_errors")
            
            # Clear write queue
            try:
                with self.queue_lock:
                    while not self.write_queue.empty():
                        try:
                            self.write_queue.get_nowait()
                        except queue.Empty:
                            break
            except Exception as e:
                self._handle_error(e, "queue cleanup", "error", "fatal_errors")
            
        except Exception as e:
            raise CSVCleanupError(f"Resource cleanup failed: {str(e)}") from e
    
    def start(self) -> None:
        """
        Start the CSV writer with error handling.
        
        Raises:
            CSVError: If start operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.running:
                self.logger.warning("CSV writer already running")
                return
            
            # Create new file
            self._create_new_file()
            
            # Start writer thread
            try:
                self.writer_thread = threading.Thread(target=self._writer_thread_func)
                self.writer_thread.daemon = True
                self.writer_thread.start()
            except Exception as e:
                raise CSVError(f"Failed to start writer thread: {str(e)}") from e
            
            # Start rotation thread
            try:
                self.rotation_thread = threading.Thread(target=self._rotation_timer)
                self.rotation_thread.daemon = True
                self.rotation_thread.start()
            except Exception as e:
                raise CSVError(f"Failed to start rotation thread: {str(e)}") from e
            
            # Update state
            self._update_state(True)
            
            self.logger.info("CSV writer started")
            
        except Exception as e:
            self._handle_error(e, "start", "error", "startup_errors")
            raise CSVError(f"Failed to start writer: {str(e)}") from e
    
    def stop(self) -> None:
        """
        Stop the CSV writer with error handling.
        
        Raises:
            CSVError: If stop operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                self.logger.warning("CSV writer already stopped")
                return
            
            # Update state first
            self._update_state(False)
            
            # Cleanup resources
            self._cleanup_resources()
            
            self.logger.info("CSV writer stopped")
            
        except Exception as e:
            self._handle_error(e, "stop", "error", "fatal_errors")
            raise CSVError(f"Failed to stop writer: {str(e)}") from e
    
    def write_flow(self, flow_metrics: Dict[str, Any]) -> None:
        """
        Write flow metrics to the CSV file with error handling.
        
        Args:
            flow_metrics: Dictionary of flow metrics
            
        Raises:
            CSVWriteError: If write operation fails
        """
        try:
            if not self.running:
                return
            
            # Make a copy of the flow metrics to avoid race conditions
            import copy
            metrics_copy = copy.deepcopy(flow_metrics)
            
            # Add to write queue
            try:
                with self.queue_lock:
                    self.write_queue.put_nowait(metrics_copy)
            except queue.Full:
                self._handle_error(
                    CSVResourceError("Write queue full"),
                    "write queue",
                    "warning",
                    "resource_errors"
                )
                
        except Exception as e:
            raise CSVWriteError(f"Failed to write flow metrics: {str(e)}") from e
    
    def _writer_thread_func(self) -> None:
        """Thread function for asynchronous writing with error handling."""
        self.logger.info("Writer thread started")
        
        while self.running or not self.write_queue.empty():
            try:
                # Get next item from queue with timeout
                try:
                    with self.queue_lock:
                        flow_metrics = self.write_queue.get(timeout=0.5)
                except queue.Empty:
                    # Check if we should continue running
                    continue
                
                # Write to file
                self._write_flow_to_file(flow_metrics)
                
                # Reset error counter on success
                self.consecutive_write_errors = 0
                
                # Mark task as done
                self.write_queue.task_done()
                
            except Exception as e:
                self._handle_write_error(e)
                
        self.logger.info("Writer thread stopped")
    
    def _write_flow_to_file(self, flow_metrics: Dict[str, Any]) -> None:
        """
        Write flow metrics to the CSV file with error handling.
        
        Args:
            flow_metrics: Dictionary of flow metrics
            
        Raises:
            CSVWriteError: If write operation fails
        """
        try:
            with self.file_lock:
                # Check if we need to rotate the file based on size
                if self.size_limit_mb > 0 and self.bytes_written >= (self.size_limit_mb * 1024 * 1024):
                    self._rotate_file()
                
                # On first write, determine columns from flow metrics
                if not self.columns:
                    self._set_columns(flow_metrics)
                
                # Format flow metrics to match CSV columns
                row = {}
                for col in self.columns:
                    if col in flow_metrics:
                        # Apply type conversion if needed
                        value = flow_metrics[col]
                        if col in self.column_types:
                            try:
                                if self.column_types[col] == 'int':
                                    value = int(value)
                                elif self.column_types[col] == 'float':
                                    value = float(value)
                                elif self.column_types[col] == 'str':
                                    value = str(value)
                            except (ValueError, TypeError):
                                # If conversion fails, use original value
                                pass
                        row[col] = value
                    else:
                        # If column is missing, use default value
                        row[col] = self._get_default_value(col)
                
                # Write to CSV
                try:
                    self.writer.writerow(row)
                    self.file.flush()
                    
                    # Update bytes written
                    self.bytes_written = self.file.tell()
                except Exception as e:
                    raise CSVWriteError(f"Failed to write to CSV: {str(e)}") from e
                    
        except Exception as e:
            raise CSVWriteError(f"Failed to write flow to file: {str(e)}") from e
    
    def _handle_write_error(self, error: Exception) -> None:
        """
        Handle write errors with error handling.
        
        Args:
            error: Exception that occurred
            
        Raises:
            CSVWriteError: If error handling fails
        """
        try:
            self.consecutive_write_errors += 1
            current_time = time.time()
            
            # Log error
            self._handle_error(error, "writer thread", "error", "write_errors")
            
            # Check error window
            if current_time - self.last_error_time > self.error_window_seconds:
                self.consecutive_write_errors = 1
            self.last_error_time = current_time
            
            # If too many consecutive errors, stop
            if self.consecutive_write_errors >= self.max_consecutive_errors:
                self.logger.critical(
                    f"Too many consecutive errors ({self.consecutive_write_errors}), stopping writer thread"
                )
                self.stop()
                return
            
            # Try to recreate the file
            try:
                self._create_new_file()
            except Exception as e:
                self._handle_error(e, "file recreation", "error", "io_errors")
            
            # Sleep briefly to avoid tight loop
            time.sleep(0.1)
            
        except Exception as e:
            raise CSVWriteError(f"Failed to handle write error: {str(e)}") from e
    
    def _create_new_file(self) -> None:
        """
        Create a new CSV file with error handling.
        
        Raises:
            CSVWriteError: If file creation fails
        """
        try:
            now = datetime.now()
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            filename = f"{self.filename_prefix}_{timestamp}.csv"
            filepath = os.path.join(self.output_dir, filename)
            
            # Create new file
            try:
                self.file = open(filepath, 'w', newline='')
                self.writer = csv.DictWriter(self.file, fieldnames=self.columns)
                self.writer.writeheader()
                self.current_filename = filepath
                self.file_start_time = time.time()
                self.bytes_written = 0
            except Exception as e:
                raise CSVIOError(f"Failed to create new file: {str(e)}") from e
            
            self.logger.info("Created new CSV file", filepath=filepath)
            
        except Exception as e:
            raise CSVWriteError(f"Failed to create new file: {str(e)}") from e
    
    def _rotate_file(self) -> None:
        """
        Rotate the current CSV file with error handling.
        
        Raises:
            CSVWriteError: If rotation fails
        """
        try:
            if not self.current_filename:
                return
            
            # Close current file
            try:
                self.file.close()
                self.file = None
                self.writer = None
            except Exception as e:
                self._handle_error(e, "file close during rotation", "error", "io_errors")
            
            # Compress old file
            try:
                self._compress_file(self.current_filename)
            except Exception as e:
                self._handle_error(e, "file compression", "error", "io_errors")
            
            # Create new file
            self._create_new_file()
            
        except Exception as e:
            raise CSVWriteError(f"Failed to rotate file: {str(e)}") from e
    
    def _rotation_timer(self) -> None:
        """Timer function for file rotation with error handling."""
        while self.running:
            try:
                current_time = time.time()
                if current_time - self.file_start_time >= (self.time_limit_min * 60):
                    self._rotate_file()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self._handle_error(e, "rotation timer", "error", "processing_errors")
                time.sleep(60)
    
    def _compress_file(self, filepath: str) -> None:
        """
        Compress a CSV file with error handling.
        
        Args:
            filepath: Path to the file to compress
            
        Raises:
            CSVWriteError: If compression fails
        """
        try:
            compressed_filepath = f"{filepath}.gz"
            
            # Compress file
            try:
                with open(filepath, 'rb') as f_in:
                    with gzip.open(compressed_filepath, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            except Exception as e:
                raise CSVIOError(f"Failed to compress file: {str(e)}") from e
            
            # Remove original file
            try:
                os.remove(filepath)
            except Exception as e:
                self._handle_error(e, "file removal after compression", "error", "io_errors")
            
            self.logger.info("Compressed file", original=filepath, compressed=compressed_filepath)
            
        except Exception as e:
            raise CSVWriteError(f"Failed to compress file: {str(e)}") from e
    
    def _set_columns(self, flow_metrics: Dict[str, Any]) -> None:
        """
        Set CSV columns from flow metrics with error handling.
        
        Args:
            flow_metrics: Dictionary of flow metrics
            
        Raises:
            CSVWriteError: If column setting fails
        """
        try:
            # Determine column order and types
            self.columns = list(flow_metrics.keys())
            self.column_types = {}
            
            for col, value in flow_metrics.items():
                if isinstance(value, int):
                    self.column_types[col] = 'int'
                elif isinstance(value, float):
                    self.column_types[col] = 'float'
                else:
                    self.column_types[col] = 'str'
            
        except Exception as e:
            raise CSVWriteError(f"Failed to set columns: {str(e)}") from e
    
    def _get_default_value(self, column: str) -> Any:
        """
        Get default value for a column with error handling.
        
        Args:
            column: Column name
            
        Returns:
            Default value for the column
            
        Raises:
            CSVWriteError: If default value retrieval fails
        """
        try:
            if column in self.column_types:
                if self.column_types[column] == 'int':
                    return 0
                elif self.column_types[column] == 'float':
                    return 0.0
            return ""
        except Exception as e:
            raise CSVWriteError(f"Failed to get default value: {str(e)}") from e
    
    def _handle_error(self, error: Exception, context: str,
                     severity: str = "error", stat_key: str = "processing_errors") -> None:
        """
        Handle errors with error handling.
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            severity: Error severity ('error' or 'warning')
            stat_key: Statistics key to update
            
        Raises:
            CSVError: If error handling fails
        """
        try:
            # Update error statistics
            self.stats[stat_key] += 1
            self.stats["total_errors"] += 1
            self.stats["last_error_time"] = time.time()
            
            # Add to error history
            self.stats["error_history"].append({
                "time": time.time(),
                "context": context,
                "error": str(error),
                "type": type(error).__name__
            })
            
            # Keep only the last 100 errors
            if len(self.stats["error_history"]) > 100:
                self.stats["error_history"] = self.stats["error_history"][-100:]
            
            # Log error
            log_method = getattr(self.logger, severity)
            log_method(
                f"Error in {context}",
                error=str(error),
                error_type=type(error).__name__,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            raise CSVError(f"Error handling failed: {str(e)}") from e

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
