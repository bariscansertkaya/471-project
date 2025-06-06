import socket
import threading
import json
import time
from PyQt6.QtCore import QThread, pyqtSignal
from message import ChatMessage
from message_cache import get_message_cache

class GatewayServer(QThread):
    """
    Gateway server that listens for incoming messages from remote gateways.
    Runs as a separate thread to handle incoming TCP connections.
    """
    message_received = pyqtSignal(str, str, str, str)  # nickname, type, data, source_gateway
    
    def __init__(self, port=42070):
        super().__init__()
        self.port = port
        self.running = False
        self.server_socket = None
        self.client_threads = []
        self.message_cache = get_message_cache()
        
    def start_server(self):
        """Start the gateway server"""
        self.running = True
        self.message_cache.start_cleanup_thread()
        self.start()
        
    def stop_server(self):
        """Stop the gateway server"""
        print("[GATEWAY-SERVER] Stopping gateway server...")
        self.running = False
        
        # Close all client connections
        for client_thread in self.client_threads:
            if client_thread.is_alive():
                client_thread.join(timeout=1)
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
            
        # Stop message cache cleanup
        self.message_cache.stop_cleanup_thread()
            
        self.wait()  # Wait for thread to finish
        print("[GATEWAY-SERVER] Gateway server stopped")
        
    def run(self):
        """Main server loop"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Timeout for accept() calls
            
            print(f"[GATEWAY-SERVER] Gateway server listening on port {self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"[GATEWAY-SERVER] New connection from {client_address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    self.client_threads.append(client_thread)
                    
                except socket.timeout:
                    # Timeout is normal, continue loop
                    continue
                except OSError:
                    # Socket closed
                    break
                    
        except Exception as e:
            print(f"[GATEWAY-SERVER] Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
                
    def handle_client(self, client_socket, client_address):
        """Handle messages from a connected gateway client"""
        try:
            while self.running:
                # Receive message length first (4 bytes)
                length_data = client_socket.recv(4)
                if not length_data:
                    break
                    
                message_length = int.from_bytes(length_data, byteorder='big')
                
                # Receive the actual message
                message_data = b''
                while len(message_data) < message_length:
                    chunk = client_socket.recv(message_length - len(message_data))
                    if not chunk:
                        break
                    message_data += chunk
                
                if len(message_data) != message_length:
                    print(f"[GATEWAY-SERVER] Incomplete message from {client_address}")
                    break
                
                # Parse the gateway message
                try:
                    gateway_message = json.loads(message_data.decode('utf-8'))
                    self.process_gateway_message(gateway_message, client_address)
                except json.JSONDecodeError as e:
                    print(f"[GATEWAY-SERVER] Invalid JSON from {client_address}: {e}")
                    
        except Exception as e:
            print(f"[GATEWAY-SERVER] Client handler error for {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"[GATEWAY-SERVER] Connection closed for {client_address}")
            
    def process_gateway_message(self, gateway_message, source_address):
        """Process a message received from a remote gateway"""
        try:
            # Extract gateway metadata
            source_gateway = gateway_message.get('source_gateway', str(source_address[0]))
            gateway_path = gateway_message.get('gateway_path', [])
            hop_count = gateway_message.get('hop_count', 0)
            
            # Extract original chat message
            chat_message_data = gateway_message.get('message', {})
            msg_id = chat_message_data.get('msg_id')
            
            print(f"[GATEWAY-SERVER] Received message from gateway {source_gateway}")
            print(f"[GATEWAY-SERVER] Path: {gateway_path}, Hops: {hop_count}")
            print(f"[GATEWAY-SERVER] Message type: {chat_message_data.get('type')}")
            print(f"[GATEWAY-SERVER] From user: {chat_message_data.get('nickname')}")
            print(f"[GATEWAY-SERVER] TTL: {chat_message_data.get('ttl', 'N/A')}")
            
            # Check for duplicate messages
            if msg_id and self.message_cache.is_message_seen(msg_id):
                print(f"[GATEWAY-SERVER] Dropping duplicate message {msg_id[:8]}...")
                return
                
            # Check TTL
            ttl = chat_message_data.get('ttl', 0)
            if ttl <= 0:
                print(f"[GATEWAY-SERVER] Dropping expired message {msg_id[:8]}... (TTL: {ttl})")
                return
                
            # Add message to cache to prevent loops
            if msg_id:
                self.message_cache.add_message(msg_id, gateway_path)
            
            # Emit signal to main application
            self.message_received.emit(
                chat_message_data.get('nickname', 'Unknown'),
                chat_message_data.get('type', 'unknown'),
                chat_message_data.get('data', ''),
                source_gateway
            )
            
        except Exception as e:
            print(f"[GATEWAY-SERVER] Error processing gateway message: {e}")


def create_gateway_message(chat_message: ChatMessage, source_gateway: str, gateway_path: list = None, hop_count: int = 0):
    """
    Create a gateway message wrapper around a chat message.
    
    Args:
        chat_message: The original chat message
        source_gateway: IP of the gateway that originated this relay
        gateway_path: List of gateways that have processed this message
        hop_count: Number of hops this message has taken
    """
    if gateway_path is None:
        gateway_path = []
        
    gateway_message = {
        'source_gateway': source_gateway,
        'gateway_path': gateway_path,
        'hop_count': hop_count,
        'timestamp': int(time.time()),
        'message': chat_message.to_dict()
    }
    
    return gateway_message


def serialize_gateway_message(gateway_message: dict) -> bytes:
    """
    Serialize a gateway message for transmission.
    Returns length-prefixed message data.
    """
    json_data = json.dumps(gateway_message).encode('utf-8')
    length_prefix = len(json_data).to_bytes(4, byteorder='big')
    return length_prefix + json_data 