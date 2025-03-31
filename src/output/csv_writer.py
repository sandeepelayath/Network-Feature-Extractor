"""
CSV Writer module for the Network Feature Extractor.
Handles the generation of CSV files with flow metrics.
"""

import os
import csv
import threading
import time
import queue
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import logging

# Import local modules
from ..core.config import Config


class CSVWriter:
    """CSV Writer for outputting flow metrics."""
    
    def __init__(self, config: Config, logger):
        """
        Initialize the CSV Writer.
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger.get_logger("output")
        
        # Get output configuration
        output_dir = self.config.get('output', 'directory', './output')
        self.filename_prefix = self.config.get('output', 'filename_prefix', 'netflow')
        self.size_limit_mb = self.config.get('output', 'rotation', {}).get('size_limit_mb', 250)
        self.time_limit_min = self.config.get('output', 'rotation', {}).get('time_limit_min', 30)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = os.path.abspath(output_dir)
        
        # CSV file and writer
        self.file = None
        self.writer = None
        self.file_lock = threading.RLock()  # Use RLock instead of Lock
        
        # Column ordering and formatting
        self.columns = []
        self.column_types = {}
        
        # File rotation
        self.current_filename = ""
        self.file_start_time = 0
        self.bytes_written = 0
        self.rotation_thread = None
        self.running = False
        
        # Write queue for asynchronous writing
        self.write_queue = queue.Queue(maxsize=10000)
        self.writer_thread = None
        
        # Error tracking
        self.consecutive_write_errors = 0
        self.max_consecutive_errors = 10
    
    def start(self) -> None:
        """Start the CSV writer."""
        self.running = True
        
        # Create initial file
        with self.file_lock:
            self._create_new_file()
        
        # Start writer thread
        self.writer_thread = threading.Thread(target=self._writer_thread_func)
        self.writer_thread.daemon = True
        self.writer_thread.start()
        
        # Start rotation thread if time-based rotation is enabled
        if self.time_limit_min > 0:
            self.rotation_thread = threading.Thread(target=self._rotation_timer)
            self.rotation_thread.daemon = True
            self.rotation_thread.start()
        
        self.logger.info("CSV writer started", output_dir=self.output_dir)
    
    def stop(self) -> None:
        """Stop the CSV writer and close the file."""
        self.running = False
        
        # Wait for writer thread to stop
        if self.writer_thread and self.writer_thread.is_alive():
            try:
                # Drain the queue first
                self.logger.info("Waiting for write queue to drain")
                while not self.write_queue.empty() and self.consecutive_write_errors < self.max_consecutive_errors:
                    time.sleep(0.1)
                self.writer_thread.join(timeout=5.0)
            except Exception as e:
                self.logger.error("Error waiting for writer thread", error=str(e))
        
        # Wait for rotation thread to stop
        if self.rotation_thread and self.rotation_thread.is_alive():
            try:
                self.rotation_thread.join(timeout=5.0)
            except Exception as e:
                self.logger.error("Error waiting for rotation thread", error=str(e))
        
        # Close the current file
        with self.file_lock:
            if self.file:
                try:
                    self.file.close()
                except Exception as e:
                    self.logger.error("Error closing CSV file", error=str(e))
                finally:
                    self.file = None
                    self.writer = None
                    self.logger.info("CSV writer stopped", filename=self.current_filename)
    
    def write_flow(self, flow_metrics: Dict[str, Any]) -> None:
        """
        Write flow metrics to the CSV file.
        
        Args:
            flow_metrics: Dictionary of flow metrics
        """
        if not self.running:
            return
        
        # Make a copy of the flow metrics to avoid race conditions
        import copy
        metrics_copy = copy.deepcopy(flow_metrics)
        
        try:
            # Add to write queue
            self.write_queue.put_nowait(metrics_copy)
        except queue.Full:
            self.logger.warning("Write queue full, dropping flow metrics")
    
    def _writer_thread_func(self) -> None:
        """Thread function for asynchronous writing."""
        self.logger.info("Writer thread started")
        
        while self.running or not self.write_queue.empty():
            try:
                # Get next item from queue with timeout
                try:
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
                self.consecutive_write_errors += 1
                self.logger.error("Error in writer thread", 
                                error=str(e), 
                                consecutive_errors=self.consecutive_write_errors)
                
                # If too many consecutive errors, break
                if self.consecutive_write_errors >= self.max_consecutive_errors:
                    self.logger.critical(f"Too many consecutive errors ({self.consecutive_write_errors}), stopping writer thread")
                    break
                
                # Sleep briefly to avoid tight loop
                time.sleep(0.1)
        
        self.logger.info("Writer thread stopped")
    
    def _write_flow_to_file(self, flow_metrics: Dict[str, Any]) -> None:
        """
        Write flow metrics to the CSV file.
        
        Args:
            flow_metrics: Dictionary of flow metrics
        """
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
                self.logger.error("Error writing to CSV", error=str(e))
                # Try to recreate the file in case it's corrupted
                self._handle_write_error()
                
    def _handle_write_error(self) -> None:
        """Handle file write errors by recreating the file."""
        try:
            self.logger.warning("Attempting to recreate CSV file after write error")
            self._create_new_file()
        except Exception as e:
            self.logger.error("Failed to recreate CSV file", error=str(e))
    
    def _create_new_file(self) -> None:
        """Create a new CSV file."""
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        filename = f"{self.filename_prefix}_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        # Close existing file if any
        if self.file:
            self.file.close()
        
        # Create new file
        try:
            self.file = open(filepath, 'w', newline='')
            self.writer = csv.DictWriter(self.file, fieldnames=self.columns if self.columns else [])
            
            # Write header if columns are known
            if self.columns:
                self.writer.writeheader()
            
            # Reset counters
            self.current_filename = filename
            self.file_start_time = time.time()
            self.bytes_written = 0
            
            self.logger.info("Created new CSV file", filename=filename)
        except Exception as e:
            self.logger.error("Failed to create CSV file", filename=filename, error=str(e))
            raise
    
    def _rotate_file(self) -> None:
        """Rotate the current file and create a new one."""
        # Only rotate if we have an existing file
        if not self.file:
            return
        
        self.logger.info("Rotating CSV file", 
                        filename=self.current_filename, 
                        size_mb=self.bytes_written / (1024 * 1024),
                        age_min=(time.time() - self.file_start_time) / 60)
        
        # Create a new file
        old_filename = self.current_filename
        self._create_new_file()
        
        # Compress the old file if configured
        if self.config.get('output', 'compression', {}).get('enabled', True):
            threading.Thread(target=self._compress_file, 
                           args=(os.path.join(self.output_dir, old_filename),)).start()
    
    def _rotation_timer(self) -> None:
        """Thread function for time-based rotation."""
        while self.running:
            time.sleep(60)  # Check every minute
            
            with self.file_lock:
                # Check if we need to rotate based on time
                if (time.time() - self.file_start_time) >= (self.time_limit_min * 60):
                    self._rotate_file()
    
    def _compress_file(self, filepath: str) -> None:
        """
        Compress a file using gzip.
        
        Args:
            filepath: Path to the file to compress
        """
        import gzip
        import shutil
        
        try:
            # Compressed file path
            compressed_filepath = filepath + ".gz"
            
            # Compress the file
            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove the original file
            os.remove(filepath)
            
            self.logger.info("Compressed file", 
                           original=filepath, 
                           compressed=compressed_filepath)
        except Exception as e:
            self.logger.error("Failed to compress file", 
                            filepath=filepath, 
                            error=str(e))
    
    def _set_columns(self, flow_metrics: Dict[str, Any]) -> None:
        """
        Set the CSV columns based on flow metrics.
        
        Args:
            flow_metrics: Dictionary of flow metrics
        """
        # Define a specific column order for better readability
        # This should match the expected format from the dataset
        ordered_columns = [
            "dst_port", "flow_duration", "total_fwd_packets", "total_bwd_packets",
            "total_length_of_fwd_packets", "total_length_of_bwd_packets",
            "fwd_packet_length_max", "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_std",
            "bwd_packet_length_max", "bwd_packet_length_min", "bwd_packet_length_mean", "bwd_packet_length_std",
            "flow_bytes_per_sec", "flow_packets_per_sec",
            "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
            "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
            "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
            "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count", 
            "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
            "down_up_ratio", "average_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
            "fwd_header_length", "fwd_avg_bytes_bulk", "fwd_avg_packets_bulk", "fwd_avg_bulk_rate",
            "bwd_avg_bytes_bulk", "bwd_avg_packets_bulk", "bwd_avg_bulk_rate",
            "subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
            "init_win_bytes_forward", "init_win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
            "active_mean", "active_std", "active_max", "active_min",
            "idle_mean", "idle_std", "idle_max", "idle_min"
        ]
        
        # Get all available metrics
        available_metrics = set(flow_metrics.keys())
        
        # Filter ordered columns to only include available metrics
        filtered_columns = [col for col in ordered_columns if col in available_metrics]
        
        # Add any remaining metrics that weren't in our predefined order
        remaining_metrics = available_metrics - set(filtered_columns)
        filtered_columns.extend(sorted(remaining_metrics))
        
        self.columns = filtered_columns
        
        # Determine column types
        for col in self.columns:
            if col in flow_metrics:
                value = flow_metrics[col]
                if isinstance(value, int):
                    self.column_types[col] = 'int'
                elif isinstance(value, float):
                    self.column_types[col] = 'float'
                else:
                    self.column_types[col] = 'str'
        
        # Write the header
        if self.writer:
            self.writer.fieldnames = self.columns
            self.writer.writeheader()
        
        self.logger.info("CSV columns set", column_count=len(self.columns))
    
    def _get_default_value(self, column: str) -> Any:
        """
        Get default value for a column based on its type.
        
        Args:
            column: Column name
            
        Returns:
            Default value
        """
        if column in self.column_types:
            if self.column_types[column] == 'int':
                return 0
            elif self.column_types[column] == 'float':
                return 0.0
        
        return ""
