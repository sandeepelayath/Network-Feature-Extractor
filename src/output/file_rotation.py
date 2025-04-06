"""
File Rotation module for the Network Feature Extractor.
Handles rotation of output files based on size and time limits with enhanced error handling and performance monitoring.
"""

import os
import time
import gzip
import shutil
import threading
import hashlib
import pathlib
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from structlog import get_logger

from ..core.config import Config
from ..logging.logger import Logger


class RotationError(Exception):
    """Base exception for file rotation errors."""
    pass

class RotationInitializationError(RotationError):
    """Exception raised during file rotator initialization."""
    pass

class RotationCleanupError(RotationError):
    """Exception raised during file rotator cleanup."""
    pass

class RotationIOError(RotationError):
    """Exception raised during I/O operations."""
    pass

class RotationConfigError(RotationError):
    """Exception raised during configuration validation."""
    pass

class RotationStateError(RotationError):
    """Exception raised during state management."""
    pass

class RotationResourceError(RotationError):
    """Exception raised when resource limits are exceeded."""
    pass

class RotationTimeoutError(RotationError):
    """Exception raised when operations timeout."""
    pass

class RotationCompressionError(RotationError):
    """Exception raised during compression operations."""
    pass


class RotationReason(Enum):
    """Enum for rotation reasons."""
    SIZE = 'size'
    TIME = 'time'
    MANUAL = 'manual'
    ERROR = 'error'


class CompressionAlgorithm(Enum):
    """Enum for compression algorithms."""
    GZIP = 'gzip'
    BZIP2 = 'bzip2'
    LZMA = 'lzma'
    NONE = 'none'


@dataclass
class FileRotationConfig:
    """File rotation configuration."""
    size_limit_mb: int
    time_limit_min: int
    compression_enabled: bool
    compression_algorithm: CompressionAlgorithm
    backup_count: int
    check_interval: int = 60
    cleanup_interval: int = 3600
    max_backup_age_days: int = 30
    preserve_original: bool = False
    hash_algorithm: str = 'sha256'


@dataclass
class FileMetadata:
    """File metadata for rotation tracking."""
    path: str
    size: int
    created: float
    modified: float
    hash: Optional[str] = None
    compressed: bool = False
    rotation_count: int = 0
    last_rotation: Optional[float] = None
    last_rotation_reason: Optional[RotationReason] = None


@dataclass
class RotationStats:
    """Rotation statistics."""
    total_rotations: int = 0
    size_rotations: int = 0
    time_rotations: int = 0
    manual_rotations: int = 0
    error_rotations: int = 0
    compressed_files: int = 0
    cleanup_count: int = 0
    total_compressed_size: int = 0
    total_original_size: int = 0
    errors: int = 0
    last_rotation_time: float = 0
    last_cleanup_time: float = 0
    rotation_times: List[float] = field(default_factory=list)
    compression_times: List[float] = field(default_factory=list)
    cleanup_times: List[float] = field(default_factory=list)
    error_history: List[Dict[str, Any]] = field(default_factory=list)


class FileRotator:
    """
    File rotation manager.
    Handles rotation of files based on size and time limits with enhanced monitoring.
    """
    
    def __init__(self, config: Config, logger_manager: Logger):
        """
        Initialize the file rotator.
        
        Args:
            config: Global configuration
            logger_manager: Logger manager
            
        Raises:
            RotationInitializationError: If initialization fails
        """
        try:
            self.config = config
            self.logger = logger_manager.get_logger()
            
            # Get output configuration
            self.output_config = self.config.get('output', {})
            self.rotation_config = self.output_config.get('rotation', {})
            self.compression_config = self.output_config.get('compression', {})
            
            # Validate configuration
            self._validate_config()
            
            # Initialize rotation configuration
            self.rotation_settings = FileRotationConfig(
                size_limit_mb=self.rotation_config.get('size_limit_mb', 250),
                time_limit_min=self.rotation_config.get('time_limit_min', 30),
                compression_enabled=self.compression_config.get('enabled', True),
                compression_algorithm=CompressionAlgorithm(
                    self.compression_config.get('algorithm', 'gzip')
                ),
                backup_count=self.output_config.get('backup_count', 5),
                check_interval=self.rotation_config.get('check_interval', 60),
                cleanup_interval=self.rotation_config.get('cleanup_interval', 3600),
                max_backup_age_days=self.rotation_config.get('max_backup_age_days', 30),
                preserve_original=self.rotation_config.get('preserve_original', False),
                hash_algorithm=self.rotation_config.get('hash_algorithm', 'sha256')
            )
            
            # Initialize state
            self.running = False
            self.rotation_thread = None
            self.cleanup_thread = None
            self.current_file: Optional[FileMetadata] = None
            self.file_lock = threading.RLock()
            self.rotation_lock = threading.RLock()
            self._is_initialized = False
            self._is_shutting_down = False
            
            # Initialize statistics
            self.stats = RotationStats()
            
            # Initialize file tracking
            self.rotated_files: Dict[str, FileMetadata] = {}
            
            # Initialize state
            self._initialize_state()
            
            self.logger.info(
                "File rotator initialized",
                size_limit=f"{self.rotation_settings.size_limit_mb}MB",
                time_limit=f"{self.rotation_settings.time_limit_min}min",
                compression_enabled=self.rotation_settings.compression_enabled,
                compression_algorithm=self.rotation_settings.compression_algorithm.value
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize file rotator: {str(e)}"
            self.logger.error(error_msg)
            raise RotationInitializationError(error_msg) from e
    
    def _validate_config(self) -> None:
        """Validate file rotation configuration."""
        try:
            # Validate size limit
            size_limit = self.rotation_config.get('size_limit_mb', 250)
            if not isinstance(size_limit, (int, float)) or size_limit <= 0:
                raise RotationConfigError("Size limit must be a positive number")
            
            # Validate time limit
            time_limit = self.rotation_config.get('time_limit_min', 30)
            if not isinstance(time_limit, (int, float)) or time_limit < 0:
                raise RotationConfigError("Time limit must be a non-negative number")
            
            # Validate backup count
            backup_count = self.output_config.get('backup_count', 5)
            if not isinstance(backup_count, int) or backup_count < 0:
                raise RotationConfigError("Backup count must be a non-negative integer")
            
            # Validate check interval
            check_interval = self.rotation_config.get('check_interval', 60)
            if not isinstance(check_interval, int) or check_interval <= 0:
                raise RotationConfigError("Check interval must be a positive integer")
            
            # Validate cleanup interval
            cleanup_interval = self.rotation_config.get('cleanup_interval', 3600)
            if not isinstance(cleanup_interval, int) or cleanup_interval <= 0:
                raise RotationConfigError("Cleanup interval must be a positive integer")
            
            # Validate max backup age
            max_backup_age = self.rotation_config.get('max_backup_age_days', 30)
            if not isinstance(max_backup_age, int) or max_backup_age <= 0:
                raise RotationConfigError("Max backup age must be a positive integer")
            
        except Exception as e:
            raise RotationConfigError(f"Configuration validation failed: {str(e)}") from e
    
    def _initialize_state(self) -> None:
        """Initialize rotator state."""
        try:
            with self.rotation_lock:
                if self._is_initialized:
                    raise RotationStateError("Rotator already initialized")
                
                self._is_initialized = True
                self._is_shutting_down = False
                self.running = False
                
                # Initialize statistics
                self.stats = RotationStats()
                
                # Initialize file tracking
                self.rotated_files = {}
                
        except Exception as e:
            raise RotationStateError(f"State initialization failed: {str(e)}") from e
    
    def _validate_state(self) -> None:
        """Validate current state of the rotator."""
        try:
            with self.rotation_lock:
                if self.running and not self.rotation_thread:
                    raise RotationStateError("Running state but no rotation thread")
                if self.running and not self.cleanup_thread:
                    raise RotationStateError("Running state but no cleanup thread")
                if self._is_shutting_down and self.running:
                    raise RotationStateError("Shutting down but still running")
        except Exception as e:
            raise RotationStateError(f"State validation failed: {str(e)}") from e
    
    def _update_state(self, new_state: bool) -> None:
        """Update rotator state with error handling."""
        try:
            with self.rotation_lock:
                old_state = self.running
                self.running = new_state
                
                if old_state != new_state:
                    self.logger.info(
                        "Rotator state changed",
                        old_state=old_state,
                        new_state=new_state
                    )
        except Exception as e:
            raise RotationStateError(f"Failed to update state: {str(e)}") from e
    
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
            RotationError: If error handling fails
        """
        try:
            # Update error statistics
            with self.rotation_lock:
                self.stats.errors += 1
                self.stats.error_history.append({
                    "time": time.time(),
                    "context": context,
                    "error": str(error),
                    "type": type(error).__name__
                })
                
                # Keep only the last 100 errors
                if len(self.stats.error_history) > 100:
                    self.stats.error_history = self.stats.error_history[-100:]
            
            # Log error
            log_method = getattr(self.logger, severity)
            log_method(
                f"Error in {context}",
                error=str(error),
                error_type=type(error).__name__,
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            raise RotationError(f"Error handling failed: {str(e)}") from e
    
    def set_current_file(self, filepath: str) -> None:
        """
        Set the current file being written to.
        
        Args:
            filepath: Path to the current file
            
        Raises:
            RotationIOError: If the file doesn't exist
            RotationError: If setting the current file fails
        """
        try:
            if not os.path.exists(filepath):
                raise RotationIOError(f"File not found: {filepath}")
            
            with self.file_lock:
                file_stat = os.stat(filepath)
                self.current_file = FileMetadata(
                    path=filepath,
                    size=file_stat.st_size,
                    created=file_stat.st_ctime,
                    modified=file_stat.st_mtime,
                    hash=self._calculate_file_hash(filepath)
                )
                
        except Exception as e:
            raise RotationError(f"Failed to set current file: {str(e)}") from e
    
    def update_file_size(self, size: int) -> None:
        """
        Update the current file size.
        
        Args:
            size: New file size in bytes
            
        Raises:
            RotationError: If updating the file size fails
        """
        try:
            with self.file_lock:
                if self.current_file:
                    self.current_file.size = size
                    self.current_file.modified = time.time()
                    
        except Exception as e:
            raise RotationError(f"Failed to update file size: {str(e)}") from e
    
    def start(self) -> bool:
        """
        Start the file rotator.
        
        Returns:
            True if started successfully, False otherwise
            
        Raises:
            RotationError: If start operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if self.running:
                self.logger.warning("File rotator already running")
                return False
            
            # Start rotation thread
            try:
                self.rotation_thread = threading.Thread(target=self._rotation_loop)
                self.rotation_thread.daemon = True
                self.rotation_thread.start()
            except Exception as e:
                raise RotationError(f"Failed to start rotation thread: {str(e)}") from e
            
            # Start cleanup thread
            try:
                self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
                self.cleanup_thread.daemon = True
                self.cleanup_thread.start()
            except Exception as e:
                raise RotationError(f"Failed to start cleanup thread: {str(e)}") from e
            
            # Update state
            self._update_state(True)
            
            self.logger.info("File rotator started")
            return True
            
        except Exception as e:
            self._handle_error(e, "start", "error", "errors")
            raise RotationError(f"Failed to start rotator: {str(e)}") from e
    
    def stop(self) -> None:
        """
        Stop the file rotator.
        
        Raises:
            RotationError: If stop operation fails
        """
        try:
            # Validate state
            self._validate_state()
            
            if not self.running:
                self.logger.warning("File rotator already stopped")
                return
            
            # Update state first
            self._update_state(False)
            
            # Stop rotation thread
            if self.rotation_thread and self.rotation_thread.is_alive():
                try:
                    self.rotation_thread.join(timeout=5.0)
                    if self.rotation_thread.is_alive():
                        self.logger.warning("Rotation thread did not stop gracefully")
                except Exception as e:
                    self._handle_error(e, "rotation thread stop", "error", "errors")
            
            # Stop cleanup thread
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                try:
                    self.cleanup_thread.join(timeout=5.0)
                    if self.cleanup_thread.is_alive():
                        self.logger.warning("Cleanup thread did not stop gracefully")
                except Exception as e:
                    self._handle_error(e, "cleanup thread stop", "error", "errors")
            
            self.logger.info("File rotator stopped")
            
        except Exception as e:
            self._handle_error(e, "stop", "error", "errors")
            raise RotationError(f"Failed to stop rotator: {str(e)}") from e
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get rotator statistics.
        
        Returns:
            Dictionary of statistics
            
        Raises:
            RotationError: If statistics retrieval fails
        """
        try:
            with self.rotation_lock:
                return {
                    'total_rotations': self.stats.total_rotations,
                    'size_rotations': self.stats.size_rotations,
                    'time_rotations': self.stats.time_rotations,
                    'manual_rotations': self.stats.manual_rotations,
                    'error_rotations': self.stats.error_rotations,
                    'compressed_files': self.stats.compressed_files,
                    'cleanup_count': self.stats.cleanup_count,
                    'total_compressed_size': self.stats.total_compressed_size,
                    'total_original_size': self.stats.total_original_size,
                    'errors': self.stats.errors,
                    'last_rotation_time': self.stats.last_rotation_time,
                    'last_cleanup_time': self.stats.last_cleanup_time,
                    'average_rotation_time': sum(self.stats.rotation_times) / len(self.stats.rotation_times) if self.stats.rotation_times else 0,
                    'average_compression_time': sum(self.stats.compression_times) / len(self.stats.compression_times) if self.stats.compression_times else 0,
                    'average_cleanup_time': sum(self.stats.cleanup_times) / len(self.stats.cleanup_times) if self.stats.cleanup_times else 0,
                    'error_history': self.stats.error_history
                }
        except Exception as e:
            raise RotationError(f"Failed to get statistics: {str(e)}") from e
    
    def _rotation_loop(self) -> None:
        """
        Main rotation loop.
        Checks file size and age at regular intervals.
        
        Raises:
            RotationError: If rotation loop fails
        """
        while self.running:
            try:
                with self.file_lock:
                    if self.current_file and os.path.exists(self.current_file.path):
                        # Check file size
                        size_mb = self.current_file.size / (1024 * 1024)
                        if size_mb >= self.rotation_settings.size_limit_mb:
                            self._rotate_file(RotationReason.SIZE)
                        
                        # Check file age
                        age_min = (time.time() - self.current_file.created) / 60
                        if age_min >= self.rotation_settings.time_limit_min:
                            self._rotate_file(RotationReason.TIME)
                
                time.sleep(self.rotation_settings.check_interval)
                
            except Exception as e:
                self._handle_error(e, "rotation loop", "error", "errors")
                time.sleep(1)  # Sleep briefly before retrying
    
    def _cleanup_loop(self) -> None:
        """
        Cleanup loop.
        Removes old rotated files at regular intervals.
        
        Raises:
            RotationError: If cleanup loop fails
        """
        while self.running:
            try:
                self._cleanup_old_files()
                time.sleep(self.rotation_settings.cleanup_interval)
                
            except Exception as e:
                self._handle_error(e, "cleanup loop", "error", "errors")
                time.sleep(1)  # Sleep briefly before retrying
    
    def _rotate_file(self, reason: RotationReason) -> None:
        """
        Rotate the current file.
        
        Args:
            reason: Reason for rotation
            
        Raises:
            RotationError: If rotation fails
        """
        start_time = time.time()
        
        try:
            if not self.current_file:
                return
            
            # Generate new filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = os.path.splitext(self.current_file.path)[0]
            ext = os.path.splitext(self.current_file.path)[1]
            rotated_file = f"{base_name}_{timestamp}{ext}"
            
            # Calculate file hash before rotation
            file_hash = self._calculate_file_hash(self.current_file.path)
            
            # Rename current file
            try:
                shutil.move(self.current_file.path, rotated_file)
            except Exception as e:
                raise RotationIOError(f"Failed to move file: {str(e)}") from e
            
            # Update file metadata
            rotated_metadata = FileMetadata(
                path=rotated_file,
                size=self.current_file.size,
                created=self.current_file.created,
                modified=time.time(),
                hash=file_hash,
                rotation_count=self.current_file.rotation_count + 1,
                last_rotation=time.time(),
                last_rotation_reason=reason
            )
            
            # Compress if enabled
            if self.rotation_settings.compression_enabled:
                try:
                    compression_start = time.time()
                    compressed_file = self._compress_file(rotated_file)
                    with self.rotation_lock:
                        self.stats.compression_times.append(time.time() - compression_start)
                        self.stats.total_compressed_size += os.path.getsize(compressed_file)
                        self.stats.total_original_size += rotated_metadata.size
                    rotated_metadata.compressed = True
                    rotated_metadata.path = compressed_file
                except Exception as e:
                    raise RotationCompressionError(f"Failed to compress file: {str(e)}") from e
            
            # Store rotated file metadata
            self.rotated_files[rotated_metadata.path] = rotated_metadata
            
            # Update statistics
            with self.rotation_lock:
                self.stats.rotation_times.append(time.time() - start_time)
                self.stats.last_rotation_time = time.time()
                self.stats.total_rotations += 1
                
                if reason == RotationReason.SIZE:
                    self.stats.size_rotations += 1
                elif reason == RotationReason.TIME:
                    self.stats.time_rotations += 1
                elif reason == RotationReason.MANUAL:
                    self.stats.manual_rotations += 1
                elif reason == RotationReason.ERROR:
                    self.stats.error_rotations += 1
            
            # Reset current file
            self.current_file = None
            
            self.logger.info(
                "File rotated",
                reason=reason.value,
                original_file=self.current_file.path if self.current_file else None,
                rotated_file=rotated_metadata.path,
                compressed=rotated_metadata.compressed
            )
            
        except Exception as e:
            with self.rotation_lock:
                self.stats.errors += 1
                self.stats.error_rotations += 1
            raise RotationError(f"Failed to rotate file: {str(e)}") from e
    
    def _cleanup_old_files(self) -> None:
        """
        Clean up old rotated files.
        
        Raises:
            RotationError: If cleanup fails
        """
        start_time = time.time()
        
        try:
            with self.rotation_lock:
                # Get files older than max age
                current_time = time.time()
                max_age_seconds = self.rotation_settings.max_backup_age_days * 24 * 3600
                
                files_to_remove = [
                    filepath for filepath, metadata in self.rotated_files.items()
                    if current_time - metadata.created > max_age_seconds
                ]
                
                # Remove old files
                for filepath in files_to_remove:
                    try:
                        os.remove(filepath)
                        del self.rotated_files[filepath]
                        self.stats.cleanup_count += 1
                    except Exception as e:
                        self._handle_error(e, "file removal", "error", "errors")
                
                # Update statistics
                self.stats.cleanup_times.append(time.time() - start_time)
                self.stats.last_cleanup_time = time.time()
                
        except Exception as e:
            raise RotationError(f"Failed to cleanup old files: {str(e)}") from e
    
    def _compress_file(self, filepath: str) -> str:
        """
        Compress a file.
        
        Args:
            filepath: Path to the file to compress
            
        Returns:
            Path to the compressed file
            
        Raises:
            RotationCompressionError: If compression fails
        """
        try:
            compressed_filepath = f"{filepath}.gz"
            
            # Compress file
            try:
                with open(filepath, 'rb') as f_in:
                    with gzip.open(compressed_filepath, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            except Exception as e:
                raise RotationIOError(f"Failed to compress file: {str(e)}") from e
            
            # Remove original file if not preserving
            if not self.rotation_settings.preserve_original:
                try:
                    os.remove(filepath)
                except Exception as e:
                    self._handle_error(e, "file removal after compression", "error", "errors")
            
            self.logger.info("Compressed file", original=filepath, compressed=compressed_filepath)
            return compressed_filepath
            
        except Exception as e:
            raise RotationCompressionError(f"Failed to compress file: {str(e)}") from e
    
    def _calculate_file_hash(self, filepath: str) -> Optional[str]:
        """
        Calculate the hash of a file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            File hash or None if calculation fails
            
        Raises:
            RotationIOError: If hash calculation fails
        """
        try:
            hash_func = getattr(hashlib, self.rotation_settings.hash_algorithm)
            with open(filepath, 'rb') as f:
                return hash_func(f.read()).hexdigest()
        except Exception as e:
            raise RotationIOError(f"Failed to calculate file hash: {str(e)}") from e

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
