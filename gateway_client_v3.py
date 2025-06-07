import socket
import threading
import time
import os
from typing import List, Dict, Optional
from PyQt6.QtCore import QThread, pyqtSignal
from message import ChatMessage
from gateway_server import create_gateway_message, serialize_gateway_message
from message_cache import get_message_cache
from connection_manager import get_connection_manager, ConnectionState
from error_handler import handle_error, ErrorCategory, ErrorSeverity
from message_retry import get_retry_system


class EnhancedGatewayClient(QThread):
    """
    Enhanced gateway client with reliable connections, error handling, and message retry.
    Integrates with Phase 3 reliability systems.
    """
    connection_status_changed = pyqtSignal(str, str)  # gateway_ip, status
    message_delivery_status = pyqtSignal(str, bool, str)  # message_id, success, details
    error_occurred = pyqtSignal(str, str, str)  # category, severity, message
    
    def __init__(self, local_gateway_ip: str = "127.0.0.1"):
        super().__init__()
        self.local_gateway_ip = local_gateway_ip
        self.running = False
        self.gateway_ips = []
        
        # Get global systems
        self.message_cache = get_message_cache()
        self.connection_manager = get_connection_manager()
        self.retry_system = get_retry_system()
        
        # Setup callbacks
        self.connection_manager.on_connection_state_change = self._on_connection_state_change
        self.connection_manager.on_error = self._on_connection_error
        
        self.retry_system.on_message_success = self._on_retry_success
        self.retry_system.on_message_failed = self._on_retry_failed
        self.retry_system.on_message_expired = self._on_retry_expired
        
        # Statistics
        self.stats = {
            "messages_sent": 0,
            "messages_failed": 0,
            "messages_retried": 0,
            "connection_failures": 0,
            "recovery_attempts": 0
        }
        
    def load_gateway_list(self, filename: str = "gateways.txt") -> List[str]:
        """Load gateway IP addresses from configuration file"""
        gateway_ips = []
        
        if not os.path.exists(filename):
            error_msg = f"Gateway file {filename} not found"
            print(f"[GATEWAY-CLIENT-V3] {error_msg}")
            
            handle_error(
                ErrorCategory.SYSTEM, ErrorSeverity.MEDIUM,
                "config_missing", error_msg,
                context={"filename": filename}
            )
            return gateway_ips
            
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        # Skip our own IP to prevent self-connection
                        if line != self.local_gateway_ip:
                            gateway_ips.append(line)
                            print(f"[GATEWAY-CLIENT-V3] Added gateway: {line}")
                        else:
                            print(f"[GATEWAY-CLIENT-V3] Skipping local IP: {line}")
                            
        except Exception as e:
            error_msg = f"Error reading gateway file: {e}"
            print(f"[GATEWAY-CLIENT-V3] {error_msg}")
            
            handle_error(
                ErrorCategory.SYSTEM, ErrorSeverity.HIGH,
                "config_read_error", error_msg,
                exception=e, context={"filename": filename}
            )
            
        return gateway_ips
    
    def start_client(self):
        """Start the enhanced gateway client"""
        try:
            # Load gateway configuration
            self.gateway_ips = self.load_gateway_list()
            if not self.gateway_ips:
                print("[GATEWAY-CLIENT-V3] No remote gateways configured")
                return
                
            # Start global systems
            self.connection_manager.start()
            self.retry_system.start()
            
            # Add gateways to connection manager
            for gateway_ip in self.gateway_ips:
                self.connection_manager.add_gateway(gateway_ip)
                
            self.running = True
            self.start()
            
            print(f"[GATEWAY-CLIENT-V3] Started with {len(self.gateway_ips)} gateways")
            
        except Exception as e:
            handle_error(
                ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL,
                "startup_failed", f"Failed to start gateway client: {e}",
                exception=e
            )
            
    def stop_client(self):
        """Stop the enhanced gateway client"""
        print("[GATEWAY-CLIENT-V3] Stopping gateway client...")
        
        try:
            self.running = False
            
            # Stop global systems
            self.retry_system.stop()
            self.connection_manager.stop()
            
            self.wait()  # Wait for main thread to finish
            print("[GATEWAY-CLIENT-V3] Gateway client stopped")
            
        except Exception as e:
            handle_error(
                ErrorCategory.SYSTEM, ErrorSeverity.MEDIUM,
                "shutdown_error", f"Error during shutdown: {e}",
                exception=e
            )
        
    def run(self):
        """Main client monitoring loop"""
        print(f"[GATEWAY-CLIENT-V3] Monitoring connections to {len(self.gateway_ips)} gateways")
        
        # Monitor and emit periodic status updates
        while self.running:
            try:
                # Emit connection status for UI updates
                connected_gateways = self.connection_manager.get_connected_gateways()
                
                for gateway_ip in self.gateway_ips:
                    status = "connected" if gateway_ip in connected_gateways else "disconnected"
                    self.connection_status_changed.emit(gateway_ip, status)
                
                # Log periodic statistics
                if hasattr(self, '_last_stats_log'):
                    if time.time() - self._last_stats_log > 300:  # Every 5 minutes
                        self._log_statistics()
                else:
                    self._last_stats_log = time.time()
                
                time.sleep(10)  # Update every 10 seconds
                
            except Exception as e:
                handle_error(
                    ErrorCategory.SYSTEM, ErrorSeverity.LOW,
                    "monitoring_error", f"Monitoring loop error: {e}",
                    exception=e
                )
                time.sleep(5)
                
    def send_message_to_gateways(self, chat_message: ChatMessage, use_retry: bool = True, 
                               priority: int = 0) -> Dict[str, str]:
        """
        Send a chat message to all connected gateways with enhanced reliability
        
        Returns dict of gateway_ip -> status
        """
        if not self.running:
            return {}
            
        results = {}
        
        try:
            # Check if we've already seen this message
            if self.message_cache.is_message_seen(chat_message.msg_id):
                print(f"[GATEWAY-CLIENT-V3] Skipping duplicate message {chat_message.msg_id[:8]}...")
                return {"status": "duplicate"}
                
            # Check TTL
            if chat_message.is_expired():
                print(f"[GATEWAY-CLIENT-V3] Skipping expired message {chat_message.msg_id[:8]}... (TTL: {chat_message.ttl})")
                return {"status": "expired"}
                
            # Add message to cache
            self.message_cache.add_message(chat_message.msg_id, [self.local_gateway_ip])
            
            # Decrement TTL for forwarding
            forwarded_message = chat_message.copy_with_decremented_ttl()
            
            # Get connected gateways
            connected_gateways = self.connection_manager.get_connected_gateways()
            
            if not connected_gateways:
                error_msg = "No gateway connections available"
                print(f"[GATEWAY-CLIENT-V3] {error_msg}")
                
                handle_error(
                    ErrorCategory.NETWORK, ErrorSeverity.MEDIUM,
                    "no_connections", error_msg,
                    context={"message_id": chat_message.msg_id}
                )
                return {"status": "no_connections"}
            
            # Send to each connected gateway
            for gateway_ip in connected_gateways:
                # Check if we should forward to this gateway
                if not self.message_cache.should_forward_to_gateway(chat_message.msg_id, gateway_ip):
                    results[gateway_ip] = "skipped_duplicate"
                    continue
                
                try:
                    if use_retry:
                        # Use retry system for reliability
                        retry_id = self.retry_system.add_message(
                            forwarded_message, gateway_ip, priority
                        )
                        results[gateway_ip] = f"queued_for_retry:{retry_id}"
                        self.stats["messages_retried"] += 1
                    else:
                        # Direct send (less reliable)
                        success = self._send_direct(forwarded_message, gateway_ip)
                        results[gateway_ip] = "sent" if success else "failed"
                        
                        if success:
                            self.stats["messages_sent"] += 1
                        else:
                            self.stats["messages_failed"] += 1
                            
                except Exception as e:
                    error_msg = f"Error sending to {gateway_ip}: {e}"
                    print(f"[GATEWAY-CLIENT-V3] {error_msg}")
                    
                    handle_error(
                        ErrorCategory.MESSAGE, ErrorSeverity.MEDIUM,
                        "send_error", error_msg,
                        exception=e, context={
                            "gateway_ip": gateway_ip,
                            "message_id": chat_message.msg_id
                        }
                    )
                    
                    results[gateway_ip] = f"error:{str(e)}"
                    self.stats["messages_failed"] += 1
            
        except Exception as e:
            error_msg = f"Critical error in send_message_to_gateways: {e}"
            print(f"[GATEWAY-CLIENT-V3] {error_msg}")
            
            handle_error(
                ErrorCategory.MESSAGE, ErrorSeverity.CRITICAL,
                "send_critical_error", error_msg,
                exception=e, context={"message_id": chat_message.msg_id}
            )
            
            results["status"] = f"critical_error:{str(e)}"
        
        return results
    
    def _send_direct(self, chat_message: ChatMessage, gateway_ip: str) -> bool:
        """Send message directly without retry system"""
        try:
            # Create gateway message wrapper
            gateway_message = create_gateway_message(
                chat_message=chat_message,
                source_gateway=self.local_gateway_ip,
                gateway_path=[self.local_gateway_ip],
                hop_count=1
            )
            
            # Serialize message
            message_data = serialize_gateway_message(gateway_message)
            
            # Send via connection manager
            success = self.connection_manager.send_to_gateway(gateway_ip, message_data)
            
            if success:
                print(f"[GATEWAY-CLIENT-V3] Direct send to {gateway_ip} successful (TTL: {chat_message.ttl})")
            else:
                print(f"[GATEWAY-CLIENT-V3] Direct send to {gateway_ip} failed")
                
            return success
            
        except Exception as e:
            print(f"[GATEWAY-CLIENT-V3] Direct send error to {gateway_ip}: {e}")
            return False
    
    def _on_connection_state_change(self, gateway_ip: str, state: ConnectionState):
        """Handle connection state changes"""
        print(f"[GATEWAY-CLIENT-V3] Connection to {gateway_ip}: {state.value}")
        
        self.connection_status_changed.emit(gateway_ip, state.value)
        
        if state == ConnectionState.FAILED:
            self.stats["connection_failures"] += 1
        elif state == ConnectionState.CONNECTED:
            self.stats["recovery_attempts"] += 1
    
    def _on_connection_error(self, gateway_ip: str, error: Exception):
        """Handle connection errors"""
        error_msg = f"Connection error to {gateway_ip}: {error}"
        print(f"[GATEWAY-CLIENT-V3] {error_msg}")
        
        self.error_occurred.emit("network", "medium", error_msg)
        
        handle_error(
            ErrorCategory.NETWORK, ErrorSeverity.MEDIUM,
            "connection_error", error_msg,
            exception=error, context={"gateway_ip": gateway_ip}
        )
    
    def _on_retry_success(self, message_id: str, retryable_msg):
        """Handle successful message retry"""
        print(f"[GATEWAY-CLIENT-V3] Retry success: {message_id}")
        self.message_delivery_status.emit(message_id, True, "Delivered successfully")
        self.stats["messages_sent"] += 1
    
    def _on_retry_failed(self, message_id: str, retryable_msg):
        """Handle failed message retry"""
        print(f"[GATEWAY-CLIENT-V3] Retry failed: {message_id}")
        self.message_delivery_status.emit(message_id, False, "All retry attempts failed")
        self.stats["messages_failed"] += 1
    
    def _on_retry_expired(self, message_id: str, retryable_msg):
        """Handle expired message retry"""
        print(f"[GATEWAY-CLIENT-V3] Retry expired: {message_id}")
        self.message_delivery_status.emit(message_id, False, "Message expired before delivery")
        self.stats["messages_failed"] += 1
    
    def _log_statistics(self):
        """Log periodic statistics"""
        conn_stats = self.connection_manager.get_connection_stats()
        retry_stats = self.retry_system.get_stats()
        
        print(f"[GATEWAY-CLIENT-V3] STATS - Messages sent: {self.stats['messages_sent']}, "
              f"Failed: {self.stats['messages_failed']}, Retried: {self.stats['messages_retried']}, "
              f"Connection failures: {self.stats['connection_failures']}")
        
        print(f"[GATEWAY-CLIENT-V3] RETRY STATS - Total: {retry_stats['total_messages']}, "
              f"Queue size: {retry_stats['current_queue_size']}, "
              f"Success: {retry_stats['successful_retries']}")
        
        self._last_stats_log = time.time()
    
    def get_connection_status(self) -> Dict[str, str]:
        """Get current connection status for all gateways"""
        connected_gateways = self.connection_manager.get_connected_gateways()
        
        status = {}
        for gateway_ip in self.gateway_ips:
            if gateway_ip in connected_gateways:
                status[gateway_ip] = "connected"
            else:
                status[gateway_ip] = "disconnected"
                
        return status
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        conn_stats = self.connection_manager.get_connection_stats()
        retry_stats = self.retry_system.get_stats()
        
        return {
            "client_stats": self.stats.copy(),
            "connection_stats": conn_stats,
            "retry_stats": retry_stats,
            "connected_gateways": len(self.connection_manager.get_connected_gateways()),
            "total_gateways": len(self.gateway_ips)
        }
    
    def force_reconnect(self, gateway_ip: Optional[str] = None):
        """Force reconnection to specific gateway or all gateways"""
        if gateway_ip:
            self.connection_manager.remove_gateway(gateway_ip)
            time.sleep(1)
            self.connection_manager.add_gateway(gateway_ip)
            print(f"[GATEWAY-CLIENT-V3] Forced reconnect to {gateway_ip}")
        else:
            for gw_ip in self.gateway_ips:
                self.connection_manager.remove_gateway(gw_ip)
            time.sleep(2)
            for gw_ip in self.gateway_ips:
                self.connection_manager.add_gateway(gw_ip)
            print("[GATEWAY-CLIENT-V3] Forced reconnect to all gateways")


def get_local_ip():
    """Get the local IP address for gateway identification"""
    try:
        # Create a dummy socket to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1" 