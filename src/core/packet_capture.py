"""
Packet Capture module for the Network Feature Extractor.
Loads and interacts with the eBPF program for packet capture.
"""

import os
import ctypes
import threading
import queue
import time
import socket
import select
import random
import errno
import struct
from typing import Dict, List, Optional, Callable, Any

from bcc import BPF
import pyroute2
from structlog import get_logger

# Import local modules
from .config import Config


# Packet metadata structure matching the eBPF program
class FlowKey(ctypes.Structure):
    _fields_ = [
        ("ip_version", ctypes.c_uint8),
        ("protocol", ctypes.c_uint8),
        ("src_addr", ctypes.c_uint32 * 4),
        ("dst_addr", ctypes.c_uint32 * 4),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
    ]


class PacketMetadata(ctypes.Structure):
    _fields_ = [
        ("key", FlowKey),
        ("timestamp_ns", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("header_size", ctypes.c_uint16),
        ("direction", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("window_size", ctypes.c_uint16),
        ("mss", ctypes.c_uint16),
        ("sampling_rate", ctypes.c_uint8),
    ]


# Enum for statistics indices (must match eBPF enum)
class StatIndices:
    PROCESSED_PACKETS = 0
    PROCESSED_BYTES = 1
    DROPPED_PACKETS = 2
    SAMPLED_PACKETS = 3
    IPV4_PACKETS = 4
    IPV6_PACKETS = 5
    UNKNOWN_PACKETS = 6
    ERROR_PACKETS = 7


# Enum for config indices (must match eBPF enum)
class ConfigIndices:
    SAMPLING_ENABLED = 0
    SAMPLING_RATE = 1
    CAPTURE_TCP = 2
    CAPTURE_UDP = 3
    CAPTURE_ICMP = 4
    CAPTURE_OTHER = 5


class PacketCapture:
    """Packet capture module using eBPF."""

    def __init__(self, interface: str, mode: str = "xdp", 
                 sample_rate: float = 1.0, ebpf_path: str = None,
                 packet_queue_size: int = 100000,
                 overflow_policy: str = "drop"):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface name
            mode: Capture mode ('xdp' or 'raw_socket')
            sample_rate: Packet sampling rate (0.0-1.0)
            ebpf_path: Path to eBPF program (default: use bundled program)
            packet_queue_size: Size of the packet queue
            overflow_policy: Policy for queue overflow ('drop' or 'block')
        """
        self.interface = interface
        self.mode = mode.lower()
        self.sample_rate = max(0.0, min(1.0, sample_rate))  # Clamp to 0.0-1.0
        self.ebpf_path = ebpf_path
        self.logger = get_logger()
        self.overflow_policy = overflow_policy.lower()
        
        if self.overflow_policy not in ["drop", "block"]:
            self.logger.warning(
                "Invalid overflow policy, using 'drop'", 
                policy=overflow_policy
            )
            self.overflow_policy = "drop"
        
        # State variables
        self.running = False
        self.processing_active = False
        self.bpf = None
        self.raw_socket = None
        self.callback = None
        self.processing_thread = None
        
        # Packet queue
        self.packet_queue = queue.Queue(maxsize=packet_queue_size)
        
        # Statistics
        self.stats = {
            "processed_packets": 0,
            "dropped_packets": 0,
            "queue_overflow": 0,  # Track queue overflow events
            "startup_errors": 0,
            "processing_errors": 0,
            "fatal_errors": 0,
            "captured_packets": 0,
            "callback_errors": 0
        }
        
        # Add a lock for thread-safe stat updates
        self.stats_lock = threading.RLock()
        
        # Track last log time for throttling
        self.last_overflow_log_time = 0
    
    def start(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """
        Start packet capture.
        
        Args:
            callback: Callback function to process packet metadata
            
        Returns:
            True if capture started successfully, False otherwise
        """
        try:
            self.logger.info("Starting packet capture", interface=self.interface, mode=self.mode)
            
            self.callback = callback
            self.running = True
            self.processing_active = True
            
            # Start the packet processing thread
            self.processing_thread = threading.Thread(target=self._process_packets, daemon=True)
            self.processing_thread.start()
            
            success = False
            original_mode = self.mode
            
            # First try with the specified mode
            if self.mode == "xdp":
                success = self._start_xdp_capture()
                
                # If XDP fails, fall back to raw socket
                if not success:
                    self.logger.warning(
                        "XDP capture failed, falling back to raw socket mode",
                        interface=self.interface
                    )
                    self.mode = "raw_socket"
                    success = self._start_raw_socket_capture()
                    
                    if success:
                        self.logger.info(
                            "Successfully fell back to raw socket mode (reduced performance)",
                            original_mode=original_mode,
                            interface=self.interface
                        )
            else:
                success = self._start_raw_socket_capture()
            
            if not success:
                self.logger.error(
                    "Failed to start packet capture with any method",
                    interface=self.interface
                )
                self.stop()
                
            return success
        except Exception as e:
            self.logger.error("Failed to start packet capture", error=str(e))
            self.stats["startup_errors"] += 1
            # Ensure resources are cleaned up
            self.stop()
            return False
    
    def _start_xdp_capture(self) -> bool:
        """
        Start XDP capture mode.
        
        Returns:
            True if started successfully, False otherwise
        """
        try:
            # Load eBPF program
            bpf_text = self._load_ebpf_program()
            
            # Update sampling rate in BPF program
            sampling_rate_int = int(self.sample_rate * 100)
            bpf_text = bpf_text.replace("SAMPLING_RATE", str(sampling_rate_int))
            
            # Compile and load BPF program
            self.bpf = BPF(text=bpf_text)
            
            # Attach XDP program to interface
            self.bpf.attach_xdp(self.interface, self.bpf.load_func("xdp_packet_capture", BPF.XDP))
            
            # Set up ring buffer to receive events
            self.bpf["metadata_ringbuf"].open_ring_buffer(self._ring_buffer_callback)
            
            self.logger.info("XDP capture started", interface=self.interface)
            
            # Start ring buffer polling thread
            threading.Thread(
                target=self._poll_ring_buffer,
                daemon=True
            ).start()
            
            return True
        except Exception as e:
            self.logger.error("Failed to start XDP capture", error=str(e))
            self.running = False
            self.processing_active = False
            return False
    
    def _start_raw_socket_capture(self) -> bool:
        """
        Start raw socket capture mode.
        
        Returns:
            True if started successfully, False otherwise
        """
        try:
            # Create raw socket
            self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # Set socket to non-blocking mode
            self.raw_socket.setblocking(False)
            
            # Bind to interface
            self.raw_socket.bind((self.interface, 0))
            
            # Start socket polling thread
            threading.Thread(
                target=self._poll_raw_socket,
                daemon=True
            ).start()
            
            self.logger.info("Raw socket capture started", interface=self.interface)
            return True
        except Exception as e:
            self.logger.error("Failed to start raw socket capture", error=str(e))
            self.running = False
            self.processing_active = False
            return False
    
    def _poll_ring_buffer(self):
        """Poll the BPF ring buffer for packets."""
        try:
            self.logger.info("BPF ring buffer polling thread started")
            
            # Poll interval
            poll_interval = 0.1  # seconds
            
            while self.running:
                try:
                    # Poll the ring buffer
                    self.bpf.ring_buffer_poll(timeout=poll_interval)
                except Exception as e:
                    self.logger.error("Error polling ring buffer", error=str(e))
                    time.sleep(0.01)  # Brief pause to avoid tight loop
            
            self.logger.info("BPF ring buffer polling thread stopped")
        except Exception as e:
            self.logger.error("Fatal error in ring buffer polling thread", error=str(e))
            self.running = False
            self.processing_active = False
    
    def _poll_raw_socket(self):
        """Poll the raw socket for packets."""
        try:
            self.logger.info("Raw socket polling thread started")
            
            while self.running:
                # Get packet data
                try:
                    # Poll socket with timeout 
                    readable, _, _ = select.select([self.raw_socket], [], [], 0.1)
                    if not readable:
                        continue
                        
                    # Read packet
                    packet_data = self.raw_socket.recv(2048)
                    
                    # Apply sampling
                    if random.random() > self.sample_rate:
                        continue
                    
                    # Parse packet (simplified - would need proper parsing in real implementation)
                    packet_dict = self._parse_raw_packet(packet_data)
                    
                    # Queue packet for processing
                    if packet_dict and not self.packet_queue.full():
                        self.packet_queue.put_nowait(packet_dict)
                        self.stats["captured_packets"] += 1
                    else:
                        self.stats["dropped_packets"] += 1
                        
                except socket.error as e:
                    if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                        self.logger.error("Error reading from raw socket", error=str(e))
                        time.sleep(0.01)  # Brief pause to avoid tight loop
                
                except Exception as e:
                    self.logger.error("Error in raw socket polling", error=str(e))
                    time.sleep(0.01)  # Brief pause to avoid tight loop
            
            self.logger.info("Raw socket polling thread stopped")
        except Exception as e:
            self.logger.error("Fatal error in raw socket polling thread", error=str(e))
            self.running = False
            self.processing_active = False
    
    def _parse_raw_packet(self, packet_data):
        """
        Parse a raw packet and extract metadata.
        
        This is a simplified implementation and would need to be expanded
        for production use to properly parse all protocols.
        
        Args:
            packet_data: Raw packet data
            
        Returns:
            Dictionary with packet metadata or None if parsing failed
        """
        try:
            # Simplified parsing - just a placeholder
            # In a real implementation, this would parse Ethernet, IP, TCP/UDP headers
            
            # Return dummy packet for now
            return {
                "timestamp": time.time(),
                "ip_version": 4,  # Assume IPv4
                "protocol": 6,    # Assume TCP
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "length": len(packet_data),
                "tcp_flags": 0,
            }
        except Exception as e:
            self.logger.error("Error parsing raw packet", error=str(e))
            return None
    
    def _process_packets(self) -> None:
        """Process packets from the queue."""
        errors_in_a_row = 0
        max_consecutive_errors = 10  # Threshold for consecutive errors
        
        try:
            self.logger.info("Packet processing thread started")
            
            while self.processing_active:
                try:
                    # Try to get a packet with a timeout to allow for checking processing_active flag
                    try:
                        packet = self.packet_queue.get(timeout=0.1)
                    except queue.Empty:
                        # No packet available, check if we should continue
                        continue
                        
                    # Process the packet
                    if self.callback:
                        self.callback(packet)
                        
                    # Update statistics
                    self.stats["processed_packets"] += 1
                    errors_in_a_row = 0  # Reset consecutive error counter
                    
                except Exception as e:
                    errors_in_a_row += 1
                    
                    # Use the error handler with severity based on consecutive errors
                    severity = "error"
                    if errors_in_a_row >= max_consecutive_errors // 2:
                        severity = "critical"
                    elif errors_in_a_row >= max_consecutive_errors // 4:
                        severity = "warning"
                        
                    self._handle_error(
                        e, 
                        "Error processing packet",
                        severity=severity,
                        stat_key="processing_errors"
                    )
                    
                    # If too many consecutive errors, break out of the loop
                    if errors_in_a_row >= max_consecutive_errors:
                        self.logger.critical(
                            f"Too many consecutive errors ({errors_in_a_row}), stopping packet processing"
                        )
                        self.processing_active = False
                        self.running = False
                        break
                        
                    # Brief pause to avoid tight loop in case of persistent errors
                    time.sleep(0.01)
                    
        except Exception as e:
            self._handle_error(
                e,
                "Fatal error in packet processing thread",
                severity="critical",
                stat_key="fatal_errors"
            )
        finally:
            self.logger.info("Packet processing thread stopped")
            self.processing_active = False
    
    def stop(self) -> None:
        """Stop packet capture."""
        self.logger.info("Stopping packet capture")
        
        # Set flags to stop threads
        self.running = False
        self.processing_active = False
        
        # Wait for processing thread to finish
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=2.0)
        
        # Clean up resources
        if self.mode == "xdp" and self.bpf:
            try:
                # Detach XDP program
                self.bpf.remove_xdp(self.interface, flags=0)
                self.bpf = None
            except Exception as e:
                self.logger.error("Error detaching XDP program", error=str(e))
                
        # Close raw socket if used
        if self.raw_socket:
            try:
                self.raw_socket.close()
                self.raw_socket = None
            except Exception as e:
                self.logger.error("Error closing raw socket", error=str(e))
                
        self.logger.info("Packet capture stopped")
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get packet capture statistics.
        
        Returns:
            Dictionary of statistics
        """
        # Create a thread-safe copy of the statistics
        with self.stats_lock:
            return self.stats.copy()  # Return a copy to avoid external modifications
    
    def _configure_ebpf(self) -> None:
        """Configure the eBPF program based on configuration."""
        if not self.bpf:
            return
        
        # Get configuration
        sampling_enabled = self.config.get('network', 'sampling', {}).get('enabled', False)
        sampling_rate = self.config.get('network', 'sampling', {}).get('rate', 0.1)
        
        # Convert sampling rate to an integer for eBPF (0-100%)
        sampling_rate_int = int(sampling_rate * 100)
        
        # Configure eBPF maps
        config_map = self.bpf["config_map"]
        
        # Convert to ctypes for eBPF
        config_map[ConfigIndices.SAMPLING_ENABLED] = ctypes.c_uint32(1 if sampling_enabled else 0)
        config_map[ConfigIndices.SAMPLING_RATE] = ctypes.c_uint32(sampling_rate_int)
        
        # Protocol configs
        config_map[ConfigIndices.CAPTURE_TCP] = ctypes.c_uint32(
            1 if self.config.is_protocol_enabled('tcp') else 0)
        config_map[ConfigIndices.CAPTURE_UDP] = ctypes.c_uint32(
            1 if self.config.is_protocol_enabled('udp') else 0)
        config_map[ConfigIndices.CAPTURE_ICMP] = ctypes.c_uint32(
            1 if self.config.is_protocol_enabled('icmp') else 0)
        config_map[ConfigIndices.CAPTURE_OTHER] = ctypes.c_uint32(
            1 if any(self.config.is_protocol_enabled(p) for p in ['quic', 'sctp', 'dccp', 'rsvp']) else 0)
        
        self.logger.info("eBPF configuration set", 
                         sampling_enabled=sampling_enabled, 
                         sampling_rate=sampling_rate)
    
    def _attach_interface(self) -> None:
        """Attach the eBPF program to the network interface."""
        if not self.bpf:
            return
        
        # Get interface from config
        interface = self.config.get('network', 'interface')
        if not interface:
            raise ValueError("Network interface not specified in configuration")
        
        # Check if interface exists
        ipr = pyroute2.IPRoute()
        try:
            idx = ipr.link_lookup(ifname=interface)[0]
        except IndexError:
            ipr.close()
            raise ValueError(f"Network interface not found: {interface}")
        finally:
            ipr.close()
        
        # Set interface to promiscuous mode if configured
        promiscuous = self.config.get('network', 'promiscuous', True)
        if promiscuous:
            self._set_promiscuous_mode(interface, True)
        
        # Try to determine if XDP is supported on this interface
        xdp_supported = self._check_xdp_support(interface)
        
        # Attach XDP program to interface if supported
        attached = False
        if xdp_supported:
            try:
                fn = self.bpf.load_func("xdp_packet_capture", BPF.XDP)
                self.bpf.attach_xdp(interface, fn, 0)
                self.logger.info("Attached XDP program to interface", 
                                interface=interface, 
                                mode="XDP",
                                performance="high")
                attached = True
            except Exception as e:
                self.logger.warning("Failed to attach XDP program, will try fallback", 
                                   interface=interface, 
                                   error=str(e))
        
        # Fallback to raw socket if XDP didn't work
        if not attached:
            try:
                fn = self.bpf.load_func("xdp_packet_capture", BPF.SOCKET_FILTER)
                self.bpf.attach_raw_socket(interface, fn)
                self.logger.warning(
                    "Attached raw socket program to interface. "
                    "Note: This has lower performance than XDP mode and may not "
                    "capture all packets at high traffic rates. Some features like "
                    "early packet dropping won't work in this mode.",
                    interface=interface,
                    mode="raw_socket",
                    performance="reduced"
                )
            except Exception as e:
                self.logger.error("Failed to attach raw socket program", interface=interface, error=str(e))
                raise ValueError(f"Could not attach to interface {interface} using any available method")
        
        # Open ring buffer for packet metadata
        self.bpf["metadata_ringbuf"].open_ring_buffer(self._ring_buffer_callback)
    
    def _check_xdp_support(self, interface: str) -> bool:
        """
        Check if XDP is supported on the given interface.
        
        Args:
            interface: Interface name
            
        Returns:
            True if XDP is supported, False otherwise
        """
        try:
            # Try to detect driver support for XDP
            # This is a basic check and might not be fully reliable
            with open(f"/sys/class/net/{interface}/device/driver/module/parameters/disable_xdp", "r") as f:
                value = f.read().strip()
                if value == "N" or value == "0":
                    return True
            return False
        except FileNotFoundError:
            # If the file doesn't exist, we can't determine XDP support
            # Try to check for known supported drivers
            try:
                result = os.popen(f"ethtool -i {interface}").read()
                driver = ""
                for line in result.splitlines():
                    if line.startswith("driver:"):
                        driver = line.split(":")[1].strip()
                        break
                
                # List of drivers known to support XDP
                xdp_drivers = ["i40e", "mlx5_core", "ixgbe", "bnxt_en", "virtio_net", "tun", "veth"]
                return driver in xdp_drivers
            except Exception:
                pass
            
            # As a last resort, assume XDP is supported and let attachment handle errors
            return True
    
    def _ring_buffer_callback(self, ctx, data, size) -> int:
        """
        Callback for ring buffer events.
        
        Args:
            ctx: BPF context
            data: Raw packet data
            size: Data size
            
        Returns:
            Integer indicating success or failure
        """
        try:
            # Parse the data - create a local immutable packet dictionary
            packet = self.bpf["metadata_ringbuf"].event(data)
            
            # Extract packet information (operations are local/immutable)
            packet_dict = {
                "timestamp": time.time(),
                "ip_version": packet.ip_version,
                "protocol": packet.protocol,
                "src_ip": self._format_ip_address(packet.src_ip, packet.ip_version),
                "dst_ip": self._format_ip_address(packet.dst_ip, packet.ip_version),
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "length": packet.length,
                "tcp_flags": packet.tcp_flags if packet.protocol == 6 else 0,
            }
            
            # Put packet in queue based on overflow policy
            try:
                if self.overflow_policy == "drop":
                    # Use put_nowait for non-blocking operation
                    self.packet_queue.put_nowait(packet_dict)
                else:  # "block" policy
                    # Use put with timeout to avoid infinite blocking
                    # A 1-second timeout is a reasonable balance
                    self.packet_queue.put(packet_dict, timeout=1.0)
                
                # Update statistics with lock protection
                with self.stats_lock:
                    self.stats["captured_packets"] += 1
            except queue.Full:
                # Handle queue full case - protected update 
                with self.stats_lock:
                    self.stats["queue_overflow"] += 1
                    self.stats["dropped_packets"] += 1
                    overflow_count = self.stats["queue_overflow"]
                
                # Throttle logging to avoid overwhelming logs
                # Log at most once per second for overflows
                current_time = time.time()
                if current_time - self.last_overflow_log_time >= 1.0:
                    self.last_overflow_log_time = current_time
                    self.logger.warning(
                        "Packet queue full, dropping packets",
                        overflow_count=overflow_count,
                        queue_size=self.packet_queue.qsize(),
                    )
            return 0
        except Exception as e:
            # Thread-safe error stats update
            with self.stats_lock:
                self.stats["callback_errors"] += 1
            self.logger.error("Error in ring buffer callback", error=str(e))
            return 0
    
    def _format_ip_address(self, addr, ip_version):
        if ip_version == 4:
            # Convert IPv4 address using socket
            try:
                # Create a 4-byte packed string
                packed = struct.pack("!I", addr & 0xFFFFFFFF)
                return socket.inet_ntop(socket.AF_INET, packed)
            except Exception:
                # Fallback to manual conversion if socket fails
                return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"
        elif ip_version == 6:
            # Use the socket library for IPv6 address formatting
            return self._int_array_to_ipv6(addr)
        else:
            raise ValueError(f"Unsupported IP version: {ip_version}")
    
    def _int_array_to_ipv6(self, addr_array) -> str:
        """
        Convert array of 4 32-bit integers to IPv6 address string.
        
        Args:
            addr_array: Array of 4 32-bit integers for IPv6 address
            
        Returns:
            IPv6 address string
        """
        try:
            # Convert to byte representation
            addr_bytes = bytearray(16)  # IPv6 address is 16 bytes
            
            for i in range(4):
                word = addr_array[i]
                # Network byte order (big-endian)
                addr_bytes[i*4] = (word >> 24) & 0xFF
                addr_bytes[i*4+1] = (word >> 16) & 0xFF
                addr_bytes[i*4+2] = (word >> 8) & 0xFF
                addr_bytes[i*4+3] = word & 0xFF
            
            # Use socket library to format the address
            return socket.inet_ntop(socket.AF_INET6, bytes(addr_bytes))
        except Exception as e:
            # Fallback in case of any error
            self._handle_error(
                e, 
                "Error formatting IPv6 address",
                severity="warning",
                stat_key="processing_errors"
            )
            
            # Return a placeholder with as much information as possible
            return f"ipv6::{addr_array[0]:x}:{addr_array[1]:x}:{addr_array[2]:x}:{addr_array[3]:x}"
    
    def _set_promiscuous_mode(self, interface: str, enable: bool) -> None:
        """
        Set or unset promiscuous mode for an interface.
        
        Args:
            interface: Interface name
            enable: True to enable, False to disable
        """
        ipr = pyroute2.IPRoute()
        try:
            idx = ipr.link_lookup(ifname=interface)[0]
            if enable:
                ipr.link('set', index=idx, promisc=1)
                self.logger.info("Enabled promiscuous mode", interface=interface)
            else:
                ipr.link('set', index=idx, promisc=0)
                self.logger.info("Disabled promiscuous mode", interface=interface)
        except Exception as e:
            self.logger.error("Failed to set promiscuous mode", 
                             interface=interface, 
                             error=str(e))
        finally:
            ipr.close()
    
    def _load_ebpf_program(self) -> str:
        """
        Load the eBPF program from file or use default.
        
        Returns:
            The eBPF program code as a string
        """
        ebpf_code = ""
        if self.ebpf_path and os.path.exists(self.ebpf_path):
            with open(self.ebpf_path, 'r') as f:
                ebpf_code = f.read()
        else:
            # Use default eBPF program path
            default_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "ebpf",
                "packet_capture.c"
            )
            
            if not os.path.exists(default_path):
                raise FileNotFoundError(f"eBPF program not found: {default_path}")
                
            with open(default_path, 'r') as f:
                ebpf_code = f.read()
                
        # Replace the ring buffer size with configured value
        ring_buffer_size = self.config.get('network', 'ring_buffer_size', 262144)
        ebpf_code = ebpf_code.replace("__uint(max_entries, 256 * 1024);", 
                                      f"__uint(max_entries, {ring_buffer_size});")
                
        return ebpf_code
    
    def is_running(self) -> bool:
        """
        Check if packet capture is running properly.
        
        Returns:
            True if capture is running, False otherwise
        """
        # Check if the main running flag is set
        if not self.running or not self.processing_active:
            return False
            
        # Check that processing thread is alive
        if not self.processing_thread or not self.processing_thread.is_alive():
            return False
            
        # Check for fatal error count
        with self.stats_lock:
            if self.stats["fatal_errors"] > 0:
                return False
                
        # Mode-specific checks
        if self.mode == "xdp":
            # Check if BPF program is loaded
            if not self.bpf:
                return False
        elif self.mode == "raw_socket":
            # Check if socket is open
            if not self.raw_socket:
                return False
                
        # All checks passed
        return True

    def _handle_error(self, error: Exception, context: str,
                     severity: str = "error", stat_key: str = "processing_errors",
                     recover_action: Callable = None) -> None:
        """
        Handle errors with a consistent policy.
        
        Args:
            error: The exception that occurred
            context: Context string for logging
            severity: Log severity (debug, info, warning, error, critical)
            stat_key: Statistics key to increment
            recover_action: Optional function to call for recovery
        """
        # Get logger method based on severity
        log_method = getattr(self.logger, severity, self.logger.error)
        
        # Log the error
        log_method(f"{context}: {str(error)}", error=str(error))
        
        # Update statistics
        with self.stats_lock:
            self.stats[stat_key] = self.stats.get(stat_key, 0) + 1
            
        # Attempt recovery if provided
        if recover_action and callable(recover_action):
            try:
                recover_action()
            except Exception as e:
                self.logger.error(
                    f"Recovery action failed: {str(e)}",
                    original_context=context,
                    recovery_error=str(e)
                )
