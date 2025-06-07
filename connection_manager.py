import socket
import threading
import time
import json
from typing import Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum
# from PyQt6.QtCore import QThread, pyqtSignal  # Not needed for core functionality


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting" 
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


@dataclass
class ConnectionStats:
    """Statistics for a gateway connection"""
    total_connects: int = 0
    total_disconnects: int = 0
    total_messages_sent: int = 0
    total_messages_received: int = 0
    total_send_failures: int = 0
    last_connect_time: Optional[float] = None
    last_disconnect_time: Optional[float] = None
    last_activity_time: Optional[float] = None
    current_state: ConnectionState = ConnectionState.DISCONNECTED


class ReliableConnection:
    """
    Manages a single reliable connection to a gateway with health monitoring,
    automatic reconnection, and message retry capabilities.
    """
    
    def __init__(self, gateway_ip: str, port: int = 42070, max_retries: int = 3):
        self.gateway_ip = gateway_ip
        self.port = port
        self.max_retries = max_retries
        self.socket: Optional[socket.socket] = None
        self.stats = ConnectionStats()
        self.state = ConnectionState.DISCONNECTED
        
        # Connection settings
        self.connect_timeout = 10  # seconds
        self.heartbeat_interval = 30  # seconds
        self.max_idle_time = 120  # seconds
        self.reconnect_delay = 5  # seconds
        self.max_reconnect_delay = 60  # seconds
        self.reconnect_backoff = 1.5  # multiplier
        
        # Threading
        self.lock = threading.RLock()
        self.running = False
        self.health_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.on_state_change: Optional[Callable[[str, ConnectionState], None]] = None
        self.on_message_received: Optional[Callable[[str, dict], None]] = None
        self.on_error: Optional[Callable[[str, Exception], None]] = None
        
    def start(self):
        """Start the connection manager"""
        with self.lock:
            if self.running:
                return
            
            self.running = True
            self.health_thread = threading.Thread(target=self._health_monitor_loop, daemon=True)
            self.health_thread.start()
            print(f"[CONN-MGR] Started connection manager for {self.gateway_ip}")
    
    def stop(self):
        """Stop the connection manager"""
        with self.lock:
            self.running = False
            self._disconnect()
            
        if self.health_thread and self.health_thread.is_alive():
            self.health_thread.join(timeout=2)
            
        print(f"[CONN-MGR] Stopped connection manager for {self.gateway_ip}")
    
    def _set_state(self, new_state: ConnectionState):
        """Update connection state and notify callbacks"""
        with self.lock:
            if self.state != new_state:
                old_state = self.state
                self.state = new_state
                self.stats.current_state = new_state
                
                print(f"[CONN-MGR] {self.gateway_ip}: {old_state.value} → {new_state.value}")
                
                if self.on_state_change:
                    try:
                        self.on_state_change(self.gateway_ip, new_state)
                    except Exception as e:
                        print(f"[CONN-MGR] Error in state change callback: {e}")
    
    def _connect(self) -> bool:
        """Attempt to establish connection"""
        try:
            self._set_state(ConnectionState.CONNECTING)
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connect_timeout)
            self.socket.connect((self.gateway_ip, self.port))
            
            # Set socket options for better reliability
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Update stats
            current_time = time.time()
            self.stats.total_connects += 1
            self.stats.last_connect_time = current_time
            self.stats.last_activity_time = current_time
            
            self._set_state(ConnectionState.CONNECTED)
            print(f"[CONN-MGR] Successfully connected to {self.gateway_ip}:{self.port}")
            return True
            
        except Exception as e:
            self._set_state(ConnectionState.FAILED)
            self._cleanup_socket()
            
            if self.on_error:
                self.on_error(self.gateway_ip, e)
            
            print(f"[CONN-MGR] Connection failed to {self.gateway_ip}: {e}")
            return False
    
    def _disconnect(self):
        """Disconnect from gateway"""
        with self.lock:
            if self.socket:
                self.stats.total_disconnects += 1
                self.stats.last_disconnect_time = time.time()
                
            self._cleanup_socket()
            
            if self.state == ConnectionState.CONNECTED:
                self._set_state(ConnectionState.DISCONNECTED)
    
    def _cleanup_socket(self):
        """Clean up socket resources"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def _health_monitor_loop(self):
        """Main health monitoring loop"""
        current_delay = self.reconnect_delay
        
        while self.running:
            try:
                with self.lock:
                    if self.state == ConnectionState.DISCONNECTED:
                        # Attempt to connect
                        if self._connect():
                            current_delay = self.reconnect_delay  # Reset delay on success
                        else:
                            # Exponential backoff
                            time.sleep(current_delay)
                            current_delay = min(current_delay * self.reconnect_backoff, 
                                              self.max_reconnect_delay)
                    
                    elif self.state == ConnectionState.CONNECTED:
                        # Check connection health
                        if self._is_connection_healthy():
                            current_delay = self.reconnect_delay  # Reset delay
                        else:
                            print(f"[CONN-MGR] Connection unhealthy, reconnecting to {self.gateway_ip}")
                            self._set_state(ConnectionState.RECONNECTING)
                            self._disconnect()
                            
                # Sleep between health checks
                time.sleep(min(5, current_delay))
                
            except Exception as e:
                print(f"[CONN-MGR] Health monitor error: {e}")
                time.sleep(5)
    
    def _is_connection_healthy(self) -> bool:
        """Check if connection is still healthy"""
        if not self.socket:
            return False
            
        try:
            # Check if socket is still writable (connection alive)
            self.socket.send(b'')  # Empty send to test connection
            
            # Check for idle timeout
            current_time = time.time()
            if (self.stats.last_activity_time and 
                current_time - self.stats.last_activity_time > self.max_idle_time):
                print(f"[CONN-MGR] Connection idle timeout for {self.gateway_ip}")
                return False
            
            return True
            
        except socket.error:
            return False
        except Exception as e:
            print(f"[CONN-MGR] Health check error: {e}")
            return False
    
    def send_message(self, message_data: bytes, retry_count: int = 0) -> bool:
        """Send message with retry logic"""
        with self.lock:
            if self.state != ConnectionState.CONNECTED or not self.socket:
                print(f"[CONN-MGR] Cannot send message - not connected to {self.gateway_ip}")
                return False
            
            try:
                # Send message length prefix + data
                self.socket.send(message_data)
                
                # Update stats
                self.stats.total_messages_sent += 1
                self.stats.last_activity_time = time.time()
                
                return True
                
            except Exception as e:
                self.stats.total_send_failures += 1
                print(f"[CONN-MGR] Send failed to {self.gateway_ip}: {e}")
                
                # Mark connection as failed
                self._set_state(ConnectionState.FAILED)
                self._disconnect()
                
                # Retry logic
                if retry_count < self.max_retries:
                    print(f"[CONN-MGR] Retrying send to {self.gateway_ip} (attempt {retry_count + 1}/{self.max_retries})")
                    time.sleep(1)  # Brief delay before retry
                    return self.send_message(message_data, retry_count + 1)
                
                if self.on_error:
                    self.on_error(self.gateway_ip, e)
                
                return False
    
    def is_connected(self) -> bool:
        """Check if currently connected"""
        with self.lock:
            return self.state == ConnectionState.CONNECTED and self.socket is not None
    
    def get_stats(self) -> ConnectionStats:
        """Get connection statistics"""
        with self.lock:
            return ConnectionStats(
                total_connects=self.stats.total_connects,
                total_disconnects=self.stats.total_disconnects,
                total_messages_sent=self.stats.total_messages_sent,
                total_messages_received=self.stats.total_messages_received,
                total_send_failures=self.stats.total_send_failures,
                last_connect_time=self.stats.last_connect_time,
                last_disconnect_time=self.stats.last_disconnect_time,
                last_activity_time=self.stats.last_activity_time,
                current_state=self.stats.current_state
            )


class ConnectionManager:
    """
    Manages multiple reliable connections to gateways with health monitoring
    and automatic recovery.
    """
    
    def __init__(self):
        self.connections: Dict[str, ReliableConnection] = {}
        self.lock = threading.RLock()
        self.running = False
        
        # Callbacks
        self.on_connection_state_change: Optional[Callable[[str, ConnectionState], None]] = None
        self.on_message_received: Optional[Callable[[str, dict], None]] = None
        self.on_error: Optional[Callable[[str, Exception], None]] = None
    
    def start(self):
        """Start the connection manager"""
        with self.lock:
            self.running = True
            print("[CONN-MGR] Connection manager started")
    
    def stop(self):
        """Stop the connection manager and all connections"""
        with self.lock:
            self.running = False
            
            for connection in self.connections.values():
                connection.stop()
            
            self.connections.clear()
            print("[CONN-MGR] Connection manager stopped")
    
    def add_gateway(self, gateway_ip: str, port: int = 42070):
        """Add a gateway to manage"""
        with self.lock:
            if gateway_ip in self.connections:
                print(f"[CONN-MGR] Gateway {gateway_ip} already managed")
                return
            
            connection = ReliableConnection(gateway_ip, port)
            connection.on_state_change = self._on_connection_state_change
            connection.on_message_received = self._on_message_received
            connection.on_error = self._on_error
            
            self.connections[gateway_ip] = connection
            
            if self.running:
                connection.start()
            
            print(f"[CONN-MGR] Added gateway {gateway_ip}")
    
    def remove_gateway(self, gateway_ip: str):
        """Remove a gateway from management"""
        with self.lock:
            if gateway_ip in self.connections:
                self.connections[gateway_ip].stop()
                del self.connections[gateway_ip]
                print(f"[CONN-MGR] Removed gateway {gateway_ip}")
    
    def send_to_gateway(self, gateway_ip: str, message_data: bytes) -> bool:
        """Send message to specific gateway"""
        with self.lock:
            if gateway_ip not in self.connections:
                print(f"[CONN-MGR] Gateway {gateway_ip} not managed")
                return False
            
            return self.connections[gateway_ip].send_message(message_data)
    
    def send_to_all_gateways(self, message_data: bytes) -> int:
        """Send message to all connected gateways"""
        success_count = 0
        
        with self.lock:
            for gateway_ip, connection in self.connections.items():
                if connection.send_message(message_data):
                    success_count += 1
        
        return success_count
    
    def get_connected_gateways(self) -> list:
        """Get list of currently connected gateways"""
        with self.lock:
            return [ip for ip, conn in self.connections.items() if conn.is_connected()]
    
    def get_connection_stats(self) -> Dict[str, ConnectionStats]:
        """Get statistics for all connections"""
        with self.lock:
            return {ip: conn.get_stats() for ip, conn in self.connections.items()}
    
    def _on_connection_state_change(self, gateway_ip: str, state: ConnectionState):
        """Handle connection state changes"""
        if self.on_connection_state_change:
            try:
                self.on_connection_state_change(gateway_ip, state)
            except Exception as e:
                print(f"[CONN-MGR] Error in state change callback: {e}")
    
    def _on_message_received(self, gateway_ip: str, message: dict):
        """Handle received messages"""
        if self.on_message_received:
            try:
                self.on_message_received(gateway_ip, message)
            except Exception as e:
                print(f"[CONN-MGR] Error in message received callback: {e}")
    
    def _on_error(self, gateway_ip: str, error: Exception):
        """Handle connection errors"""
        print(f"[CONN-MGR] Error from {gateway_ip}: {error}")
        
        if self.on_error:
            try:
                self.on_error(gateway_ip, error)
            except Exception as e:
                print(f"[CONN-MGR] Error in error callback: {e}")


# Global connection manager instance
global_connection_manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager instance"""
    return global_connection_manager 