"""
Flow Tracker module for the Network Feature Extractor.
Tracks flow state and calculates flow-level metrics.
"""

import time
import logging
import threading
from typing import Dict, List, Any, Callable, Optional
from collections import defaultdict
from datetime import datetime
import copy

from structlog import get_logger

# Import local modules
from .config import Config


class Flow:
    """
    Class representing a network flow with associated metrics.
    
    Thread Safety Note:
    This class is not thread-safe on its own and should only be accessed
    while holding the FlowTracker's flow_lock. Do not expose Flow objects
    outside of FlowTracker's protected methods.
    """
    
    def __init__(self, flow_key: Dict[str, Any], timestamp: float):
        """
        Initialize a new flow.
        
        Args:
            flow_key: Dictionary containing flow key information
            timestamp: Flow start timestamp
        """
        # Flow key
        self.ip_version = flow_key["ip_version"]
        self.protocol = flow_key["protocol"]
        self.src_ip = flow_key["src_ip"]
        self.dst_ip = flow_key["dst_ip"]
        self.src_port = flow_key["src_port"]
        self.dst_port = flow_key["dst_port"]
        
        # Flow timestamps
        self.start_time = timestamp
        self.last_update_time = timestamp
        self.end_time = 0  # Will be set when flow completes
        
        # Initialize basic metrics
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        
        # Packet length metrics
        self.fwd_pkt_len_max = 0
        self.fwd_pkt_len_min = float('inf')
        self.fwd_pkt_len_total = 0
        self.fwd_pkt_len_squared_sum = 0  # For standard deviation calculation
        
        self.bwd_pkt_len_max = 0
        self.bwd_pkt_len_min = float('inf')
        self.bwd_pkt_len_total = 0
        self.bwd_pkt_len_squared_sum = 0  # For standard deviation calculation
        
        # Inter-arrival time metrics
        self.flow_iat_total = 0
        self.flow_iat_max = 0
        self.flow_iat_min = float('inf')
        self.flow_iat_squared_sum = 0  # For standard deviation calculation
        self.flow_iat_count = 0
        
        self.fwd_iat_total = 0
        self.fwd_iat_max = 0
        self.fwd_iat_min = float('inf')
        self.fwd_iat_squared_sum = 0
        self.fwd_iat_count = 0
        self.fwd_last_timestamp = timestamp
        
        self.bwd_iat_total = 0
        self.bwd_iat_max = 0
        self.bwd_iat_min = float('inf')
        self.bwd_iat_squared_sum = 0
        self.bwd_iat_count = 0
        self.bwd_last_timestamp = timestamp
        
        # Flag metrics
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0
        
        # TCP window metrics
        self.init_win_bytes_fwd = 0
        self.init_win_bytes_bwd = 0
        
        # Active/idle metrics
        self.active_time = 0
        self.idle_time = 0
        self.active_start = timestamp
        self.idle_start = 0
        self.active_count = 1  # Start in active state
        self.idle_count = 0
        
        # Activity threshold (1 second by default)
        self.activity_timeout = 1.0
        
        # List of raw packet data for debugging (optional)
        self.packets = []
    
    def update(self, packet: Dict[str, Any], store_packets: bool = False) -> None:
        """
        Update flow with a new packet.
        
        Args:
            packet: Packet metadata dictionary
            store_packets: Whether to store raw packet data
        """
        timestamp = packet["timestamp"]
        length = packet.get("length", 0)  # Use length from packet
        direction = self._determine_direction(packet)
        
        # Store packet for debugging if requested
        if store_packets:
            self.packets.append(packet)
        
        # Check if we need to transition from idle to active
        if self.idle_start > 0 and timestamp - self.last_update_time > self.activity_timeout:
            # Calculate idle time
            idle_time = timestamp - self.idle_start
            self.idle_time += idle_time
            self.idle_count += 1
            
            # Start new active period
            self.active_start = timestamp
            self.active_count += 1
        
        # Update last update time
        prev_timestamp = self.last_update_time
        self.last_update_time = timestamp
        
        # Calculate flow IAT
        if self.flow_iat_count > 0:
            iat = timestamp - prev_timestamp
            self.flow_iat_total += iat
            self.flow_iat_max = max(self.flow_iat_max, iat)
            self.flow_iat_min = min(self.flow_iat_min, iat)
            self.flow_iat_squared_sum += iat * iat
        
        self.flow_iat_count += 1
        
        # Update direction-specific metrics
        if direction == "forward":
            # Packet counts and sizes
            self.fwd_packets += 1
            self.fwd_bytes += length
            
            # Packet length statistics
            self.fwd_pkt_len_max = max(self.fwd_pkt_len_max, length)
            self.fwd_pkt_len_min = min(self.fwd_pkt_len_min, length)
            self.fwd_pkt_len_total += length
            self.fwd_pkt_len_squared_sum += length * length
            
            # Inter-arrival time
            if self.fwd_iat_count > 0:
                iat = timestamp - self.fwd_last_timestamp
                self.fwd_iat_total += iat
                self.fwd_iat_max = max(self.fwd_iat_max, iat)
                self.fwd_iat_min = min(self.fwd_iat_min, iat)
                self.fwd_iat_squared_sum += iat * iat
            
            self.fwd_iat_count += 1
            self.fwd_last_timestamp = timestamp
            
            # Window size for first packet
            if self.fwd_packets == 1 and "window_size" in packet:
                self.init_win_bytes_fwd = packet["window_size"]
            
        else:  # backward
            # Packet counts and sizes
            self.bwd_packets += 1
            self.bwd_bytes += length
            
            # Packet length statistics
            self.bwd_pkt_len_max = max(self.bwd_pkt_len_max, length)
            self.bwd_pkt_len_min = min(self.bwd_pkt_len_min, length)
            self.bwd_pkt_len_total += length
            self.bwd_pkt_len_squared_sum += length * length
            
            # Inter-arrival time
            if self.bwd_iat_count > 0:
                iat = timestamp - self.bwd_last_timestamp
                self.bwd_iat_total += iat
                self.bwd_iat_max = max(self.bwd_iat_max, iat)
                self.bwd_iat_min = min(self.bwd_iat_min, iat)
                self.bwd_iat_squared_sum += iat * iat
            
            self.bwd_iat_count += 1
            self.bwd_last_timestamp = timestamp
            
            # Window size for first backward packet
            if self.bwd_packets == 1 and "window_size" in packet:
                self.init_win_bytes_bwd = packet["window_size"]
        
        # Update flag counters
        if "flags" in packet:
            flags = packet["flags"]
            if flags & 0x01:
                self.fin_count += 1
            if flags & 0x02:
                self.syn_count += 1
            if flags & 0x04:
                self.rst_count += 1
            if flags & 0x08:
                self.psh_count += 1
            if flags & 0x10:
                self.ack_count += 1
            if flags & 0x20:
                self.urg_count += 1
            if flags & 0x40:
                self.cwe_count += 1
            if flags & 0x80:
                self.ece_count += 1
    
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """
        Check if the flow has expired.
        
        Args:
            current_time: Current timestamp
            timeout: Flow timeout in seconds
            
        Returns:
            True if the flow has expired, False otherwise
        """
        return current_time - self.last_update_time > timeout
    
    def is_complete(self) -> bool:
        """
        Check if the flow has completed normally.
        
        Returns:
            True if the flow has completed, False otherwise
        """
        # TCP flow termination
        if self.protocol == 6:  # TCP
            return self.fin_count > 0 or self.rst_count > 0
        
        # For other protocols, consider flow complete if it has bidirectional traffic
        return self.fwd_packets > 0 and self.bwd_packets > 0
    
    def finalize(self, timestamp: float) -> None:
        """
        Finalize the flow for export.
        
        Args:
            timestamp: Flow end timestamp
        """
        self.end_time = timestamp
        
        # Finalize active/idle times
        if self.active_start > 0:
            # Close the active period
            self.active_time += timestamp - self.active_start
        
        # Fix min values if no packets were seen
        if self.fwd_pkt_len_min == float('inf'):
            self.fwd_pkt_len_min = 0
        if self.bwd_pkt_len_min == float('inf'):
            self.bwd_pkt_len_min = 0
        if self.flow_iat_min == float('inf'):
            self.flow_iat_min = 0
        if self.fwd_iat_min == float('inf'):
            self.fwd_iat_min = 0
        if self.bwd_iat_min == float('inf'):
            self.bwd_iat_min = 0
    
    def get_flow_key(self) -> str:
        """
        Get a string representation of the flow key.
        
        Returns:
            Flow key string
        """
        return f"{self.ip_version}_{self.protocol}_{self.src_ip}_{self.dst_ip}_{self.src_port}_{self.dst_port}"
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get all flow metrics as a dictionary.
        
        Returns:
            Dictionary of flow metrics
        """
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        duration = self.end_time - self.start_time
        
        # Calculate derived metrics with numerical stability checks
        flow_bytes_per_sec = total_bytes / max(duration, 0.001) if duration > 0 else 0
        flow_packets_per_sec = total_packets / max(duration, 0.001) if duration > 0 else 0
        
        # Mean packet lengths with zero division protection
        fwd_pkt_len_mean = self.fwd_pkt_len_total / max(self.fwd_packets, 1) if self.fwd_packets > 0 else 0
        bwd_pkt_len_mean = self.bwd_pkt_len_total / max(self.bwd_packets, 1) if self.bwd_packets > 0 else 0
        
        # Standard deviations with numerically stable algorithm
        fwd_pkt_len_std = 0
        if self.fwd_packets > 1:
            # Use a more numerically stable algorithm
            variance = max(0, (self.fwd_pkt_len_squared_sum / self.fwd_packets) - (fwd_pkt_len_mean ** 2))
            fwd_pkt_len_std = variance ** 0.5
        
        bwd_pkt_len_std = 0
        if self.bwd_packets > 1:
            # Use a more numerically stable algorithm
            variance = max(0, (self.bwd_pkt_len_squared_sum / self.bwd_packets) - (bwd_pkt_len_mean ** 2))
            bwd_pkt_len_std = variance ** 0.5
        
        # IAT means with zero division protection
        flow_iat_count_safe = max(self.flow_iat_count, 1)
        fwd_iat_count_safe = max(self.fwd_iat_count, 1)
        bwd_iat_count_safe = max(self.bwd_iat_count, 1)
        
        flow_iat_mean = self.flow_iat_total / flow_iat_count_safe if self.flow_iat_count > 0 else 0
        fwd_iat_mean = self.fwd_iat_total / fwd_iat_count_safe if self.fwd_iat_count > 0 else 0
        bwd_iat_mean = self.bwd_iat_total / bwd_iat_count_safe if self.bwd_iat_count > 0 else 0
        
        # IAT standard deviations with numerically stable algorithm
        flow_iat_std = 0
        if self.flow_iat_count > 1:
            variance = max(0, (self.flow_iat_squared_sum / flow_iat_count_safe) - (flow_iat_mean ** 2))
            flow_iat_std = variance ** 0.5
        
        fwd_iat_std = 0
        if self.fwd_iat_count > 1:
            variance = max(0, (self.fwd_iat_squared_sum / fwd_iat_count_safe) - (fwd_iat_mean ** 2))
            fwd_iat_std = variance ** 0.5
        
        bwd_iat_std = 0
        if self.bwd_iat_count > 1:
            variance = max(0, (self.bwd_iat_squared_sum / bwd_iat_count_safe) - (bwd_iat_mean ** 2))
            bwd_iat_std = variance ** 0.5
        
        # Active/idle time statistics with zero division protection
        active_count_safe = max(self.active_count, 1)
        idle_count_safe = max(self.idle_count, 1)
        
        active_mean = self.active_time / active_count_safe if self.active_count > 0 else 0
        active_std = 0  # We would need to track individual active periods to calculate this
        active_max = self.active_time  # Approximation
        active_min = self.active_time / active_count_safe if self.active_count > 0 else 0  # Approximation
        
        idle_mean = self.idle_time / idle_count_safe if self.idle_count > 0 else 0
        idle_std = 0  # We would need to track individual idle periods to calculate this
        idle_max = self.idle_time  # Approximation
        idle_min = self.idle_time / idle_count_safe if self.idle_count > 0 else 0  # Approximation
        
        # Calculate packet length variance with numerical stability
        pkt_len_variance = 0
        if total_packets > 1:
            pkt_len_mean = (self.fwd_pkt_len_total + self.bwd_pkt_len_total) / max(total_packets, 1)
            pkt_len_variance = max(0, 
                ((self.fwd_pkt_len_squared_sum + self.bwd_pkt_len_squared_sum) / max(total_packets, 1)) - 
                (pkt_len_mean ** 2)
            )
        
        # Return all metrics as a dictionary
        return {
            # Flow identification
            "ip_version": self.ip_version,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            
            # Basic metrics
            "flow_duration": duration,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_length_of_fwd_packets": self.fwd_bytes,
            "total_length_of_bwd_packets": self.bwd_bytes,
            
            # Packet length statistics
            "fwd_packet_length_max": self.fwd_pkt_len_max,
            "fwd_packet_length_min": self.fwd_pkt_len_min,
            "fwd_packet_length_mean": fwd_pkt_len_mean,
            "fwd_packet_length_std": fwd_pkt_len_std,
            "bwd_packet_length_max": self.bwd_pkt_len_max,
            "bwd_packet_length_min": self.bwd_pkt_len_min,
            "bwd_packet_length_mean": bwd_pkt_len_mean,
            "bwd_packet_length_std": bwd_pkt_len_std,
            
            # Flow rate statistics
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            
            # IAT statistics
            "flow_iat_mean": flow_iat_mean,
            "flow_iat_std": flow_iat_std,
            "flow_iat_max": self.flow_iat_max,
            "flow_iat_min": self.flow_iat_min,
            "fwd_iat_total": self.fwd_iat_total,
            "fwd_iat_mean": fwd_iat_mean,
            "fwd_iat_std": fwd_iat_std,
            "fwd_iat_max": self.fwd_iat_max,
            "fwd_iat_min": self.fwd_iat_min,
            "bwd_iat_total": self.bwd_iat_total,
            "bwd_iat_mean": bwd_iat_mean,
            "bwd_iat_std": bwd_iat_std,
            "bwd_iat_max": self.bwd_iat_max,
            "bwd_iat_min": self.bwd_iat_min,
            
            # Flag statistics
            "fin_flag_count": self.fin_count,
            "syn_flag_count": self.syn_count,
            "rst_flag_count": self.rst_count,
            "psh_flag_count": self.psh_count,
            "ack_flag_count": self.ack_count,
            "urg_flag_count": self.urg_count,
            "cwe_flag_count": self.cwe_count,
            "ece_flag_count": self.ece_count,
            
            # Down/up ratio with zero division protection
            "down_up_ratio": self.bwd_bytes / max(self.fwd_bytes, 1) if self.fwd_bytes > 0 else 0,
            
            # Average packet size with zero division protection
            "average_packet_size": (self.fwd_bytes + self.bwd_bytes) / max(self.fwd_packets + self.bwd_packets, 1) if (self.fwd_packets + self.bwd_packets) > 0 else 0,
            "avg_fwd_segment_size": self.fwd_bytes / max(self.fwd_packets, 1) if self.fwd_packets > 0 else 0,
            "avg_bwd_segment_size": self.bwd_bytes / max(self.bwd_packets, 1) if self.bwd_packets > 0 else 0,
            
            # Header length
            "fwd_header_length": self.fwd_packets * 40,  # Approximation
            
            # Bulk statistics (simplified)
            "fwd_avg_bytes_bulk": 0,  # Would require more detailed packet analysis
            "fwd_avg_packets_bulk": 0,
            "fwd_avg_bulk_rate": 0,
            "bwd_avg_bytes_bulk": 0,
            "bwd_avg_packets_bulk": 0,
            "bwd_avg_bulk_rate": 0,
            
            # Subflow statistics
            "subflow_fwd_packets": self.fwd_packets,
            "subflow_fwd_bytes": self.fwd_bytes,
            "subflow_bwd_packets": self.bwd_packets,
            "subflow_bwd_bytes": self.bwd_bytes,
            
            # Init window statistics
            "init_win_bytes_forward": self.init_win_bytes_fwd,
            "init_win_bytes_backward": self.init_win_bytes_bwd,
            "act_data_pkt_fwd": self.fwd_packets,
            "min_seg_size_forward": 0,  # Would require more detailed packet analysis
            
            # Active/idle statistics
            "active_mean": active_mean,
            "active_std": active_std,
            "active_max": active_max,
            "active_min": active_min,
            "idle_mean": idle_mean,
            "idle_std": idle_std,
            "idle_max": idle_max,
            "idle_min": idle_min,
            
            # Other features
            "packet_length_variance": pkt_len_variance,
        }

    def _determine_direction(self, packet: Dict[str, Any]) -> str:
        """
        Determine packet direction relative to flow.
        
        Args:
            packet: Packet metadata dictionary
            
        Returns:
            'forward' or 'backward'
        """
        if (packet["src_ip"] == self.src_ip and 
            packet["dst_ip"] == self.dst_ip and
            packet["src_port"] == self.src_port and
            packet["dst_port"] == self.dst_port):
            return "forward"
        else:
            return "backward"


class FlowTracker:
    """
    Flow tracker for maintaining flow state and calculating metrics.
    
    Thread Safety:
    This class uses RLock to ensure thread-safe access to the flow dictionary.
    All operations that access or modify flow objects are protected by this lock.
    External code should not access Flow objects directly, but only through
    the methods provided by this class.
    """
    
    def __init__(self, config: Config, logger_manager):
        """
        Initialize the flow tracker.
        
        Args:
            config: Configuration object
            logger_manager: Logger manager instance
        """
        self.config = config
        self.logger = logger_manager.get_logger("flow_tracker")
        
        # Flow storage sharding to reduce lock contention
        self.shard_count = 16  # Number of shards (must be a power of 2)
        self.active_flows = [{} for _ in range(self.shard_count)]
        self.flow_locks = [threading.RLock() for _ in range(self.shard_count)]
        
        # Callback for completed flows
        self.complete_flow_callback = None
        
        # Default timeout for flows (5 minutes)
        self.default_timeout = 300
        
        # Statistics
        self.stats = {
            "processed_packets": 0,
            "active_flows": 0,
            "completed_flows": 0,
            "expired_flows": 0,
            "ignored_packets": 0,
            "protocol_stats": defaultdict(int),
            "errors": 0
        }
        
        # Lock for thread-safe statistics updates
        self.stats_lock = threading.RLock()
        
        # Configure cleanup settings
        self.cleanup_interval = self.config.get('flow_tracker', 'cleanup_interval', 10)
        self.cleanup_threshold = self.config.get('flow_tracker', 'cleanup_threshold', 10000)
        self.enable_dynamic_cleanup = self.config.get('flow_tracker', 'enable_dynamic_cleanup', True)
        
        # Maximum number of active flows to track
        self.max_flows = self.config.get('flow_tracker', 'max_flows', 1000000)
        
        self.cleanup_thread = None
        self.running = True
    
    def start(self) -> None:
        """Start the flow tracker."""
        self.logger.info("Starting flow tracker", 
                         cleanup_interval=self.cleanup_interval,
                         cleanup_threshold=self.cleanup_threshold,
                         dynamic_cleanup=self.enable_dynamic_cleanup)
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_thread_func)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
    
    def process_packet(self, packet: Dict[str, Any]) -> None:
        """
        Process a packet and update flow state.
        
        Args:
            packet: Packet metadata dictionary
        """
        # Extract flow key information
        flow_key_dict = {
            "ip_version": packet["ip_version"],
            "protocol": packet["protocol"],
            "src_ip": packet["src_ip"],
            "dst_ip": packet["dst_ip"],
            "src_port": packet["src_port"],
            "dst_port": packet["dst_port"],
        }
        
        # Generate a string key for the flow
        flow_key = self._generate_flow_key(flow_key_dict)
        
        # Update statistics
        with self.stats_lock:
            self.stats["processed_packets"] += 1
            protocol_name = self._protocol_num_to_name(packet["protocol"])
            self.stats["protocol_stats"][protocol_name] += 1
        
        # Acquire lock for the entire flow processing to ensure thread safety
        with self.flow_locks[hash(flow_key) % self.shard_count]:
            # Check if flow exists
            if flow_key in self.active_flows[hash(flow_key) % self.shard_count]:
                # Update existing flow
                flow = self.active_flows[hash(flow_key) % self.shard_count][flow_key]
                
                # Update flow with the packet
                flow.update(packet)
                
                # Check if flow has completed
                if flow.is_complete():
                    # Create a deep copy of the flow metrics before releasing the lock
                    # This ensures we don't have race conditions when exporting to CSV
                    flow.finalize(packet["timestamp"])
                    metrics = flow.get_metrics()  # Get metrics while holding the lock
                    
                    # Remove flow from active flows
                    del self.active_flows[hash(flow_key) % self.shard_count][flow_key]
                    
                    # Update flow statistics
                    with self.stats_lock:
                        self.stats["completed_flows"] += 1
                        self.stats["active_flows"] = len(self.active_flows)
                    
                    # Call callback outside the lock to avoid potential deadlocks
                    if self.complete_flow_callback:
                        try:
                            # Schedule callback to run in a separate thread to avoid blocking
                            threading.Thread(
                                target=self._safe_callback,
                                args=(metrics,),
                                daemon=True
                            ).start()
                        except Exception as e:
                            self.logger.error("Error scheduling flow callback", error=str(e))
                            with self.stats_lock:
                                self.stats["errors"] += 1
            else:
                # Check if we've reached the maximum flow limit
                if len(self.active_flows) >= self.max_flows:
                    # Force removal of oldest flow
                    self._remove_oldest_flow()
                    # Log warning about hitting limit
                    self.logger.warning(
                        "Max flow limit reached, removing oldest flow",
                        max_flows=self.max_flows
                    )
                    with self.stats_lock:
                        self.stats["dropped_flows"] = self.stats.get("dropped_flows", 0) + 1
                
                # Create new flow
                flow = Flow(flow_key_dict, packet["timestamp"])
                flow.update(packet)
                shard_id = hash(flow_key) % self.shard_count
                self.active_flows[shard_id][flow_key] = flow
                
                # We'll leave the active_flows count to be updated by get_statistics
                # to avoid having to lock all shards for an accurate count
    
    def register_flow_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Register a callback function for completed flows.
        
        Args:
            callback: Function to call with flow metrics dictionary
        """
        self.complete_flow_callback = callback
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get flow tracker statistics.
        
        Returns:
            Dictionary of statistics
        """
        with self.stats_lock:
            # Update active flows count
            total_flows = 0
            for i in range(self.shard_count):
                with self.flow_locks[i]:
                    total_flows += len(self.active_flows[i])
            
            self.stats["active_flows"] = total_flows
            # Return a copy to avoid external modifications
            return self.stats.copy()
    
    def cleanup(self) -> None:
        """Clean up resources and stop threads."""
        self.logger.info("Cleaning up flow tracker")
        
        # Stop cleanup thread
        self.running = False
        
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            try:
                self.cleanup_thread.join(timeout=5.0)
            except Exception as e:
                self.logger.error("Error stopping cleanup thread", error=str(e))
                
        # Process any remaining flows
        with self.flow_lock:
            # Create a copy of active flows for safe iteration during cleanup
            for flow in list(self.active_flows.values()):
                # Finalize the flow
                flow.finalize(time.time())
                
                # Export metrics if callback is registered
                if self.complete_flow_callback:
                    try:
                        metrics = flow.get_metrics()
                        self.complete_flow_callback(metrics)
                    except Exception as e:
                        self.logger.error("Error in flow callback during cleanup", error=str(e))
                        with self.stats_lock:
                            self.stats["errors"] += 1
            
            # Clear active flows
            flow_count = len(self.active_flows)
            self.active_flows.clear()
            self.logger.info("Completed all active flows during cleanup", count=flow_count)
            
        self.logger.info("Flow tracker cleaned up")
    
    def _generate_flow_key(self, flow_dict: Dict[str, Any]) -> tuple:
        """
        Generate a tuple key for a flow.
        
        Args:
            flow_dict: Flow key information
            
        Returns:
            Flow key tuple
        """
        # Create a tuple that can be used as a dictionary key
        # The order of elements is important for consistency
        return (
            flow_dict['ip_version'],
            flow_dict['protocol'],
            flow_dict['src_ip'],
            flow_dict['dst_ip'],
            flow_dict['src_port'],
            flow_dict['dst_port']
        )
    
    def _safe_callback(self, metrics: Dict[str, Any]) -> None:
        """
        Execute the flow callback safely in a separate thread.
        
        Args:
            metrics: Flow metrics dictionary
        """
        try:
            if self.complete_flow_callback:
                # Create a deep copy of metrics to ensure immutability
                metrics_copy = copy.deepcopy(metrics)
                self.complete_flow_callback(metrics_copy)
        except Exception as e:
            self.logger.error("Error in flow callback", error=str(e))
            with self.stats_lock:
                self.stats["errors"] += 1
    
    def _complete_flow(self, flow: Flow) -> None:
        """
        Process a completed flow and remove it from active flows.
        
        Args:
            flow: Flow object
        """
        # Get flow metrics (while holding the flow_lock which is acquired by the caller)
        metrics = flow.get_metrics()
        
        # Remove flow from active flows
        flow_key = flow.get_flow_key()
        shard_id = hash(flow_key) % self.shard_count
        
        # Flow lock should already be held by the caller
        if flow_key in self.active_flows[shard_id]:
            del self.active_flows[shard_id][flow_key]
        
        # Update statistics
        with self.stats_lock:
            self.stats["completed_flows"] += 1
            self.stats["active_flows"] = len(self.active_flows)
        
        # Call callback if registered (in a separate thread for thread safety)
        if self.complete_flow_callback:
            try:
                # Schedule callback to run in a separate thread to avoid blocking
                threading.Thread(
                    target=self._safe_callback,
                    args=(metrics,),
                    daemon=True
                ).start()
            except Exception as e:
                self.logger.error("Error scheduling flow callback", error=str(e))
                with self.stats_lock:
                    self.stats["errors"] += 1
    
    def get_protocol_timeout(self, protocol: int) -> int:
        """
        Get timeout for a protocol.
        
        Args:
            protocol: Protocol number
            
        Returns:
            Timeout in seconds
        """
        protocol_name = self._protocol_num_to_name(protocol)
        return self.config.get_protocol_timeout(protocol_name, default=self.default_timeout)
    
    def _protocol_num_to_name(self, protocol: int) -> str:
        """
        Convert protocol number to name.
        
        Args:
            protocol: Protocol number
            
        Returns:
            Protocol name
        """
        protocol_map = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            33: "dccp",
            46: "rsvp",
            132: "sctp",
            # Add more protocol mappings as needed
        }
        
        return protocol_map.get(protocol, "unknown")

    def _cleanup_flows(self) -> None:
        """Check for expired flows and remove them."""
        current_time = time.time()
        expired_flows = []
        
        # Process each shard
        for shard_id in range(self.shard_count):
            with self.flow_locks[shard_id]:
                # Create a copy of the flow dictionary items to safely iterate
                # while potentially modifying the original dictionary during cleanup.
                # This prevents ConcurrentModificationExceptions.
                for flow_key, flow in list(self.active_flows[shard_id].items()):
                    # Get timeout for the protocol
                    protocol = flow.protocol
                    timeout = self.get_protocol_timeout(protocol)
                    
                    # Check if flow has expired
                    if flow.last_update_time + timeout < current_time:
                        # Flow has expired
                        flow.finalize(current_time)
                        expired_flows.append(flow)
                
                # Remove expired flows and call callbacks
                for flow in expired_flows:
                    self._complete_flow(flow)
                    
                if expired_flows:
                    self.logger.info("Cleaned up expired flows", count=len(expired_flows))
                    with self.stats_lock:
                        self.stats["expired_flows"] += len(expired_flows)
                
                # Clear expired_flows for next shard
                expired_flows = []
    
    def _cleanup_thread_func(self) -> None:
        """Thread function for periodic flow cleanup."""
        self.logger.info("Flow cleanup thread started")
        
        last_cleanup_time = time.time()
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        # Add a check for the running flag to allow clean termination
        while self.running:
            try:
                # Sleep for a short interval to allow for more responsive shutdown
                time.sleep(1.0)
                
                # Exit if running flag is cleared
                if not self.running:
                    break
                
                current_time = time.time()
                time_since_cleanup = current_time - last_cleanup_time
                
                # Check if it's time to clean up based on interval or high flow count
                should_cleanup = time_since_cleanup >= self.cleanup_interval
                
                # Dynamic cleanup: more aggressive cleanup if many active flows
                flow_count = 0
                for shard_id in range(self.shard_count):
                    with self.flow_locks[shard_id]:
                        flow_count += len(self.active_flows[shard_id])
                        
                if self.enable_dynamic_cleanup and flow_count > self.cleanup_threshold:
                    # More frequent cleanup when we have many flows
                    should_cleanup = should_cleanup or time_since_cleanup >= (self.cleanup_interval / 2)
                    
                    # Log when we reach high flow counts
                    if flow_count > self.cleanup_threshold and time_since_cleanup >= 60:
                        self.logger.warning(
                            "High number of active flows, increasing cleanup frequency",
                            active_flows=flow_count,
                            threshold=self.cleanup_threshold
                        )
                
                if should_cleanup:
                    self._cleanup_flows()
                    last_cleanup_time = current_time
                    consecutive_failures = 0  # Reset failure counter on success
                    
                    # Log statistics periodically
                    with self.stats_lock:
                        active_flow_count = flow_count  # Reuse the count we already have
                        completed_flow_count = self.stats["completed_flows"]
                    
                    self.logger.info(
                        "Flow statistics",
                        active_flows=active_flow_count,
                        completed_flows=completed_flow_count
                    )
                    
            except Exception as e:
                consecutive_failures += 1
                self.logger.error("Error in flow cleanup thread", error=str(e))
                
                # If too many consecutive failures, restart the thread
                if consecutive_failures >= max_consecutive_failures:
                    self.logger.warning(
                        "Too many consecutive failures in cleanup thread, restarting",
                        failures=consecutive_failures
                    )
                    # Reset timer to prevent immediate cleanup after restart
                    last_cleanup_time = time.time()
                    consecutive_failures = 0
                
                # Sleep to avoid tight loop in case of persistent errors
                time.sleep(5.0)
                
        self.logger.info("Flow cleanup thread stopped")

    def _remove_oldest_flow(self) -> None:
        """
        Remove the oldest flow based on last update time.
        This method must be called with flow_lock already acquired.
        """
        if not self.active_flows:
            return
            
        oldest_key = None
        oldest_time = float('inf')
        
        # Find the oldest flow
        for key, flow in self.active_flows.items():
            if flow.last_update_time < oldest_time:
                oldest_time = flow.last_update_time
                oldest_key = key
                
        # Remove the oldest flow
        if oldest_key:
            # Finalize metrics but don't call callback
            flow = self.active_flows[oldest_key]
            flow.finalize(time.time())
            del self.active_flows[oldest_key]
