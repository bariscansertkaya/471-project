#!/usr/bin/env python3
"""
Test script for Gateway functionality.
This script can be used to test gateway communication between different instances.
"""

import time
import sys
from message import ChatMessage
from gateway_server import GatewayServer, create_gateway_message
from gateway_client import GatewayClient, get_local_ip

def test_gateway_server():
    """Test the gateway server functionality"""
    print("=== Testing Gateway Server ===")
    
    server = GatewayServer(port=42070)
    
    def on_message(nickname, msg_type, data, source_gateway):
        print(f"Received: {msg_type} from {nickname} via {source_gateway}")
        print(f"Data: {data}")
    
    server.message_received.connect(on_message)
    server.start_server()
    
    print("Gateway server started on port 42070")
    print("Press Ctrl+C to stop...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop_server()
        print("Server stopped")

def test_gateway_client():
    """Test the gateway client functionality"""
    print("=== Testing Gateway Client ===")
    
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")
    
    client = GatewayClient(local_ip)
    
    def on_connection_change(gateway_ip, connected):
        status = "Connected" if connected else "Disconnected"
        print(f"Gateway {gateway_ip}: {status}")
    
    client.connection_status_changed.connect(on_connection_change)
    client.start_client()
    
    print("Gateway client started")
    print("Waiting for connections...")
    
    # Wait a bit for connections to establish
    time.sleep(3)
    
    # Send a test message
    test_message = ChatMessage("chat", "TestUser", "Hello from gateway test!")
    client.send_message_to_gateways(test_message)
    print("Test message sent to gateways")
    
    # Keep running
    try:
        while True:
            connected = client.get_connected_gateways()
            print(f"Connected gateways: {connected}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping client...")
        client.stop_client()
        print("Client stopped")

def test_message_creation():
    """Test gateway message creation and serialization"""
    print("=== Testing Message Creation ===")
    
    # Create a test chat message
    chat_msg = ChatMessage("chat", "TestUser", "Hello World!")
    print(f"Original message: {chat_msg.to_json()}")
    
    # Create gateway wrapper
    gateway_msg = create_gateway_message(
        chat_message=chat_msg,
        source_gateway="192.168.1.100",
        gateway_path=["192.168.1.100"],
        hop_count=1
    )
    
    print(f"Gateway message: {gateway_msg}")
    
    # Test serialization
    from gateway_server import serialize_gateway_message
    serialized = serialize_gateway_message(gateway_msg)
    print(f"Serialized length: {len(serialized)} bytes")
    
    print("Message creation test completed")

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_gateway.py [server|client|message]")
        print("  server  - Test gateway server")
        print("  client  - Test gateway client") 
        print("  message - Test message creation")
        return
    
    mode = sys.argv[1].lower()
    
    if mode == "server":
        test_gateway_server()
    elif mode == "client":
        test_gateway_client()
    elif mode == "message":
        test_message_creation()
    else:
        print(f"Unknown mode: {mode}")
        print("Use 'server', 'client', or 'message'")

if __name__ == "__main__":
    main() 