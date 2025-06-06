import socket
import threading
import time
import os
from typing import List, Dict
from PyQt6.QtCore import QThread, pyqtSignal
from message import ChatMessage
from gateway_server import create_gateway_message, serialize_gateway_message
from message_cache import get_message_cache


class GatewayClient(QThread):
    """
    Gateway client that manages connections to remote gateways and forwards local messages.
    """
    connection_status_changed = pyqtSignal(str, bool)  # gateway_ip, connected
    
    def __init__(self, local_gateway_ip: str = "127.0.0.1"):
        super().__init__()
        self.local_gateway_ip = local_gateway_ip
        self.running = False
        self.gateway_ips = []
        self.connections = {}  # gateway_ip -> socket
        self.connection_threads = {}  # gateway_ip -> thread
        self.reconnect_delay = 5  # seconds
        self.message_cache = get_message_cache()
        
    def load_gateway_list(self, filename: str = "gateways.txt") -> List[str]:
        """Load gateway IP addresses from configuration file"""
        gateway_ips = []
        
        if not os.path.exists(filename):
            print(f"[GATEWAY-CLIENT] Gateway file {filename} not found")
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
                            print(f"[GATEWAY-CLIENT] Added gateway: {line}")
                        else:
                            print(f"[GATEWAY-CLIENT] Skipping local IP: {line}")
                            
        except Exception as e:
            print(f"[GATEWAY-CLIENT] Error reading gateway file: {e}")
            
        return gateway_ips
    
    def start_client(self):
        """Start the gateway client"""
        self.gateway_ips = self.load_gateway_list()
        if not self.gateway_ips:
            print("[GATEWAY-CLIENT] No remote gateways configured")
            return
            
        self.running = True
        self.start()
        
    def stop_client(self):
        """Stop the gateway client"""
        print("[GATEWAY-CLIENT] Stopping gateway client...")
        self.running = False
        
        # Close all connections
        for gateway_ip, sock in self.connections.items():
            try:
                sock.close()
            except:
                pass
                
        # Wait for connection threads to finish
        for gateway_ip, thread in self.connection_threads.items():
            if thread.is_alive():
                thread.join(timeout=1)
                
        self.connections.clear()
        self.connection_threads.clear()
        self.wait()  # Wait for main thread to finish
        print("[GATEWAY-CLIENT] Gateway client stopped")
        
    def run(self):
        """Main client loop - manages connections to all gateways"""
        print(f"[GATEWAY-CLIENT] Starting connections to {len(self.gateway_ips)} gateways")
        
        # Start connection threads for each gateway
        for gateway_ip in self.gateway_ips:
            thread = threading.Thread(
                target=self.maintain_connection,
                args=(gateway_ip,),
                daemon=True
            )
            thread.start()
            self.connection_threads[gateway_ip] = thread
            
        # Monitor connections
        while self.running:
            time.sleep(1)
            
    def maintain_connection(self, gateway_ip: str):
        """Maintain persistent connection to a specific gateway"""
        port = 42070  # Gateway server port
        
        while self.running:
            try:
                print(f"[GATEWAY-CLIENT] Connecting to {gateway_ip}:{port}")
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)  # Connection timeout
                sock.connect((gateway_ip, port))
                
                print(f"[GATEWAY-CLIENT] Connected to gateway {gateway_ip}")
                self.connections[gateway_ip] = sock
                self.connection_status_changed.emit(gateway_ip, True)
                
                # Keep connection alive
                while self.running:
                    time.sleep(1)
                    
                    # Test if connection is still alive
                    try:
                        sock.send(b'')  # Empty send to test connection
                    except:
                        print(f"[GATEWAY-CLIENT] Connection to {gateway_ip} lost")
                        break
                        
            except Exception as e:
                print(f"[GATEWAY-CLIENT] Connection error to {gateway_ip}: {e}")
                
            finally:
                # Clean up connection
                if gateway_ip in self.connections:
                    try:
                        self.connections[gateway_ip].close()
                    except:
                        pass
                    del self.connections[gateway_ip]
                    
                self.connection_status_changed.emit(gateway_ip, False)
                
                # Wait before reconnecting
                if self.running:
                    print(f"[GATEWAY-CLIENT] Reconnecting to {gateway_ip} in {self.reconnect_delay} seconds")
                    time.sleep(self.reconnect_delay)
                    
    def send_message_to_gateways(self, chat_message: ChatMessage):
        """Send a chat message to all connected gateways with loop prevention"""
        if not self.running:
            return
            
        if not self.connections:
            print("[GATEWAY-CLIENT] No gateway connections available")
            return
            
        # Check if we've already seen this message
        if self.message_cache.is_message_seen(chat_message.msg_id):
            print(f"[GATEWAY-CLIENT] Skipping duplicate message {chat_message.msg_id[:8]}...")
            return
            
        # Check TTL
        if chat_message.is_expired():
            print(f"[GATEWAY-CLIENT] Skipping expired message {chat_message.msg_id[:8]}... (TTL: {chat_message.ttl})")
            return
            
        # Add message to cache
        self.message_cache.add_message(chat_message.msg_id, [self.local_gateway_ip])
        
        # Decrement TTL for forwarding
        forwarded_message = chat_message.copy_with_decremented_ttl()
        
        # Create gateway message wrapper
        gateway_message = create_gateway_message(
            chat_message=forwarded_message,
            source_gateway=self.local_gateway_ip,
            gateway_path=[self.local_gateway_ip],
            hop_count=1
        )
        
        # Serialize message
        try:
            message_data = serialize_gateway_message(gateway_message)
        except Exception as e:
            print(f"[GATEWAY-CLIENT] Error serializing message: {e}")
            return
            
        # Send to gateways that aren't in the message path
        successful_sends = 0
        for gateway_ip, sock in list(self.connections.items()):
            # Check if we should forward to this gateway
            if not self.message_cache.should_forward_to_gateway(chat_message.msg_id, gateway_ip):
                continue
                
            try:
                sock.send(message_data)
                successful_sends += 1
                print(f"[GATEWAY-CLIENT] Message sent to gateway {gateway_ip} (TTL: {forwarded_message.ttl})")
                
                # Add this gateway to the message path
                self.message_cache.add_gateway_to_path(chat_message.msg_id, gateway_ip)
                
            except Exception as e:
                print(f"[GATEWAY-CLIENT] Failed to send to {gateway_ip}: {e}")
                # Connection will be detected as failed in maintain_connection
                
        print(f"[GATEWAY-CLIENT] Message sent to {successful_sends}/{len(self.connections)} gateways")
        
    def get_connection_status(self) -> Dict[str, bool]:
        """Get current connection status for all gateways"""
        status = {}
        for gateway_ip in self.gateway_ips:
            status[gateway_ip] = gateway_ip in self.connections
        return status
        
    def get_connected_gateways(self) -> List[str]:
        """Get list of currently connected gateways"""
        return list(self.connections.keys())


def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except:
        return "127.0.0.1" 