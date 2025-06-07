from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QWidget, QListWidget, QMessageBox, QInputDialog
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import platform
import sys
import os
import time
from scapy.all import sniff, Raw

from crypto_utils import generate_key_pair, load_keys, export_public_key_base64
from message import ChatMessage
from packet_sender import send_encrypted_message, send_raw_message, send_encrypted_broadcast
from packet_receiver import INTERFACE, DEST_PORT
from peer_manager import PeerManager
from gateway_server import GatewayServer
from gateway_client import GatewayClient, get_local_ip
from message_cache import get_message_cache
# Phase 3: Reliability & Error Handling
from connection_manager import get_connection_manager
from error_handler import get_error_handler, ErrorCategory, ErrorSeverity
from message_retry import get_retry_system
from gateway_client_v3 import EnhancedGatewayClient
# Message Fragmentation
from message_fragmenter import get_message_fragmenter, MessageFragment


class NetworkReceiver(QThread):
    message_received = pyqtSignal(str, str, str, str)  # nickname, type, data, source

    def __init__(self, private_key):
        super().__init__()
        self.private_key = private_key
        self.running = False
        self.fragmenter = get_message_fragmenter()

    def handle_packet(self, packet):
        if not packet.haslayer(Raw):
            return
        
        raw_data = packet[Raw].load
        print(f"[DEBUG] NetworkReceiver: Received packet with {len(raw_data)} bytes")
        
        # Try encrypted message first
        try:
            print("[DEBUG] Attempting to decrypt message...")
            message = ChatMessage.decrypt(raw_data, self.private_key)
            if message:
                print(f"[DEBUG] Successfully decrypted {message.type} message from {message.nickname}")
                
                # Check if this is a fragment
                if message.type == "fragment":
                    self.handle_fragment(message)
                    return
                
                self.message_received.emit(message.nickname, message.type, message.data, "local")
                return
        except Exception as e:
            print(f"[DEBUG] Decryption failed (this is normal for raw messages): {e}")

        # Try raw message
        try:
            print("[DEBUG] Attempting to parse as raw message...")
            message = ChatMessage.from_bytes(raw_data)
            if message:
                print(f"[DEBUG] Successfully parsed raw {message.type} message from {message.nickname}")
                
                # Check if this is a fragment
                if message.type == "fragment":
                    self.handle_fragment(message)
                    return
                
                self.message_received.emit(message.nickname, message.type, message.data, "local")
                return
        except Exception as e:
            print(f"[DEBUG] Raw message parsing failed: {e}")
            
        print("[DEBUG] Packet could not be parsed as either encrypted or raw message")

    def handle_fragment(self, message: ChatMessage):
        """Handle fragment messages and attempt reassembly"""
        try:
            # Convert to MessageFragment
            fragment = MessageFragment.from_chat_message(message)
            if not fragment:
                print("[DEBUG] Failed to parse fragment from chat message")
                return
            
            print(f"[DEBUG] Received fragment {fragment.part_idx + 1}/{fragment.total_parts} for message {fragment.original_msg_id[:8]}...")
            
            # Process fragment with fragmenter
            complete_message = self.fragmenter.process_fragment(fragment)
            
            if complete_message:
                print(f"[DEBUG] Message reassembly complete! Original type: {complete_message.type}")
                self.message_received.emit(complete_message.nickname, complete_message.type, 
                                         complete_message.data, "local")
            else:
                print(f"[DEBUG] Fragment processed, waiting for more parts...")
                
        except Exception as e:
            print(f"[ERROR] Error handling fragment: {e}")
            import traceback
            traceback.print_exc()

    def run(self):
        self.running = True
        try:
            sniff(
                iface=INTERFACE,
                prn=self.handle_packet,
                filter=f"udp port {DEST_PORT}",
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            print(f"[!] Network receiver error: {e}")

    def stop(self):
        self.running = False


class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anonymous Chat Network")
        self.resize(800, 600)

        self.private_key = None
        self.public_key = None
        self.nickname = None
        self.is_connected = False
        self.is_gateway_mode = False
        self.network_receiver = None
        self.peer_manager = PeerManager()
        
        # Gateway components
        self.gateway_server = None
        self.gateway_client = None
        self.local_gateway_ip = get_local_ip()
        self.message_cache = get_message_cache()
        
        # Phase 3: Reliability components
        self.connection_manager = get_connection_manager()
        self.error_handler = get_error_handler()
        self.retry_system = get_retry_system()
        self.enhanced_gateway_client = None
        self.use_enhanced_client = True  # Toggle for Phase 3 features
        
        # Message fragmentation
        self.fragmenter = get_message_fragmenter()

        self.init_ui()
        self.load_existing_keys()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.append("🔐 Anonymous P2P Chat Network")
        self.chat_display.append("📝 Use File > Generate Keys to create your key pair")
        self.chat_display.append("🌐 Use File > Connect to Network to start chatting")
        self.chat_display.append("📦 Large message fragmentation enabled!")

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message... (Connect to network first)")
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)

        self.user_list = QListWidget()
        self.user_list.addItem("📡 Network Status: Disconnected")
        self.user_list.addItem(f"🌐 Local IP: {self.local_gateway_ip}")
        self.user_list.addItem("🔗 Gateway Status: Disabled")
        self.user_list.addItem("🛡️ Cache: 0 messages")
        self.user_list.addItem("⚡ Reliability: Not initialized")
        self.user_list.addItem("❌ Errors: 0")
        self.user_list.addItem("🔄 Retry Queue: 0")
        self.user_list.addItem("📦 Fragments: 0 partial")

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)

        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.chat_display)
        left_layout.addLayout(input_layout)

        main_layout.addLayout(left_layout, 3)
        main_layout.addWidget(self.user_list, 1)

        central_widget.setLayout(main_layout)
        self.setup_menus()

    def setup_menus(self):
        self.menu_bar = self.menuBar()
        if platform.system() == 'Darwin':
            self.menu_bar.setNativeMenuBar(False)

        file_menu = self.menu_bar.addMenu("File")
        preferences_menu = self.menu_bar.addMenu("Preferences")
        help_menu = self.menu_bar.addMenu("Help")

        self.action_generate_keys = QAction("Generate Keys", self)
        self.action_generate_keys.triggered.connect(self.generate_keys)

        self.action_connect = QAction("Connect to Network", self)
        self.action_connect.triggered.connect(self.connect_to_network)

        self.action_disconnect = QAction("Disconnect from Network", self)
        self.action_disconnect.triggered.connect(self.disconnect_from_network)
        self.action_disconnect.setEnabled(False)

        self.action_exit = QAction("&Exit", self)
        self.action_exit.triggered.connect(self.close)

        self.action_toggle_mode = QAction("Toggle Client/Gateway Mode", self)
        self.action_toggle_mode.triggered.connect(self.toggle_mode)

        self.action_about = QAction("About Developer", self)
        self.action_about.triggered.connect(self.show_about)

        self.action_show_debug_info = QAction("Show Debug Info", self)
        self.action_show_debug_info.triggered.connect(self.show_debug_info)

        # New menu for large message testing
        self.action_send_large_message = QAction("Send Large Test Message", self)
        self.action_send_large_message.triggered.connect(self.send_large_test_message)
        self.action_send_large_message.setEnabled(False)

        file_menu.addAction(self.action_generate_keys)
        file_menu.addAction(self.action_connect)
        file_menu.addAction(self.action_disconnect)
        file_menu.addSeparator()
        file_menu.addAction(self.action_exit)

        preferences_menu.addAction(self.action_toggle_mode)
        preferences_menu.addAction(self.action_send_large_message)
        
        help_menu.addAction(self.action_about)
        help_menu.addAction(self.action_show_debug_info)

    def load_existing_keys(self):
        try:
            if os.path.exists("keys/privkey.pem") and os.path.exists("keys/pubkey.pem"):
                self.private_key, self.public_key = load_keys()
                self.chat_display.append("🔑 Existing RSA keys loaded successfully!")
                self.action_connect.setEnabled(True)
        except Exception as e:
            print(f"[!] Error loading existing keys: {e}")

    def generate_keys(self):
        try:
            self.private_key, self.public_key = generate_key_pair()
            self.chat_display.append("🔑 RSA 2048-bit key pair generated successfully!")
            self.action_connect.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Key Generation Error", f"Failed to generate keys: {e}")

    def connect_to_network(self):
        if not self.private_key or not self.public_key:
            QMessageBox.warning(self, "No Keys", "Please generate RSA keys first!")
            return

        nickname, ok = QInputDialog.getText(self, "Connect to Network", "Enter your nickname:")
        if not ok or not nickname.strip():
            return

        self.nickname = nickname.strip()
        self.is_connected = True

        # Update UI
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.action_send_large_message.setEnabled(True)
        self.action_connect.setEnabled(False)
        self.action_disconnect.setEnabled(True)
        self.user_list.item(0).setText("📡 Network Status: Connected")

        # Start network receiver
        self.network_receiver = NetworkReceiver(self.private_key)
        self.network_receiver.message_received.connect(self.on_message_received)
        self.network_receiver.start()

        # Start gateway services if in gateway mode
        if self.is_gateway_mode:
            self.start_gateway_services()

        self.chat_display.append(f"🌐 Connected as '{self.nickname}'")
        self.send_join_message()

    def disconnect_from_network(self):
        if self.is_connected:
            self.send_quit_message()

        self.is_connected = False
        self.nickname = None

        # Update UI
        self.message_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.action_send_large_message.setEnabled(False)
        self.action_connect.setEnabled(True)
        self.action_disconnect.setEnabled(False)
        self.user_list.item(0).setText("📡 Network Status: Disconnected")

        # Stop network receiver
        if self.network_receiver:
            self.network_receiver.stop()
            self.network_receiver = None

        # Stop gateway services
        self.stop_gateway_services()

        # Clear peer list
        self.peer_manager.clear_peers()
        self.update_user_list()

        self.chat_display.append("❌ Disconnected from network")

    def send_message(self):
        if not self.is_connected or not self.nickname:
            return

        message_text = self.message_input.text().strip()
        if not message_text:
            return

        try:
            # Create message
            msg = ChatMessage("chat", self.nickname, message_text)
            
            # Check if message needs fragmentation
            if self.fragmenter.needs_fragmentation(msg):
                message_size = len(msg.to_json().encode('utf-8'))
                self.chat_display.append(f"📦 Large message detected ({message_size} bytes), fragmenting...")
            
            # Display in chat
            timestamp = time.strftime("%H:%M:%S")
            self.chat_display.append(f"[{timestamp}] {self.nickname}: {message_text}")

            # Send to all known peers (broadcast encryption)
            if self.peer_manager.peers:
                recipient_pubkeys = {nickname: peer["public_key"] for nickname, peer in self.peer_manager.peers.items()}
                success_count = send_encrypted_broadcast(msg, recipient_pubkeys)
                print(f"[DEBUG] Encrypted broadcast sent to {success_count}/{len(recipient_pubkeys)} peers")
            else:
                print("[DEBUG] No known peers for encrypted broadcast")

            # Clear input
            self.message_input.clear()

        except Exception as e:
            print(f"[ERROR] Send message failed: {e}")
            QMessageBox.critical(self, "Send Error", f"Failed to send message: {e}")

    def send_large_test_message(self):
        """Send a large test message to test fragmentation"""
        if not self.is_connected:
            QMessageBox.warning(self, "Not Connected", "Please connect to network first!")
            return
        
        # Generate a large message (1KB of Lorem Ipsum)
        large_text = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 50)[:1000]
        
        try:
            msg = ChatMessage("chat", self.nickname, large_text)
            message_size = len(msg.to_json().encode('utf-8'))
            
            self.chat_display.append(f"🧪 Sending large test message ({message_size} bytes)...")
            
            # Display in chat (truncated)
            timestamp = time.strftime("%H:%M:%S")
            display_text = large_text[:100] + "..." if len(large_text) > 100 else large_text
            self.chat_display.append(f"[{timestamp}] {self.nickname}: {display_text}")
            
            # Send to all known peers
            if self.peer_manager.peers:
                recipient_pubkeys = {nickname: peer["public_key"] for nickname, peer in self.peer_manager.peers.items()}
                success_count = send_encrypted_broadcast(msg, recipient_pubkeys)
                self.chat_display.append(f"📦 Large message sent to {success_count} peers via fragmentation")
            else:
                self.chat_display.append("⚠️ No known peers to send large message to")
                
        except Exception as e:
            print(f"[ERROR] Send large message failed: {e}")
            QMessageBox.critical(self, "Send Error", f"Failed to send large message: {e}")

    def send_join_message(self):
        try:
            public_key_b64 = export_public_key_base64(self.public_key)
            msg = ChatMessage("join", self.nickname, public_key_b64)
            
            print(f"[DEBUG] Sending JOIN message, my pubkey length: {len(public_key_b64)}")
            self.chat_display.append(f"🔍 DEBUG: Sending JOIN with pubkey length {len(public_key_b64)}")

            # JOIN messages are large, use fragmentation for raw broadcast
            message_size = len(msg.to_json().encode('utf-8'))
            if message_size > 200:
                self.chat_display.append(f"📦 JOIN message is large ({message_size} bytes), using fragmentation")
            
            print("[DEBUG] Broadcasting JOIN message with fragmentation support")
            send_raw_message(msg)
            
            # Forward JOIN to remote gateways if in gateway mode
            if self.is_gateway_mode:
                if self.enhanced_gateway_client:
                    results = self.enhanced_gateway_client.send_message_to_gateways(msg, use_retry=True, priority=2)
                    print(f"[GATEWAY-V3] JOIN message forwarded to remote gateways: {results}")
                elif self.gateway_client:
                    self.gateway_client.send_message_to_gateways(msg)
                    print("[GATEWAY] JOIN message forwarded to remote gateways")

        except Exception as e:
            print(f"[ERROR] Failed to send join message: {e}")
            self.chat_display.append(f"❌ Join message failed: {e}")

    def send_quit_message(self):
        try:
            msg = ChatMessage("quit", self.nickname, "User disconnected")
            
            # Send to all known peers
            if self.peer_manager.peers:
                recipient_pubkeys = {nickname: peer["public_key"] for nickname, peer in self.peer_manager.peers.items()}
                send_encrypted_broadcast(msg, recipient_pubkeys)
                print(f"[DEBUG] QUIT message sent to {len(recipient_pubkeys)} peers")
            
            # Forward QUIT to remote gateways if in gateway mode
            if self.is_gateway_mode:
                if self.enhanced_gateway_client:
                    results = self.enhanced_gateway_client.send_message_to_gateways(msg, use_retry=True, priority=1)
                    print(f"[GATEWAY-V3] QUIT message forwarded to remote gateways: {results}")
                elif self.gateway_client:
                    self.gateway_client.send_message_to_gateways(msg)
                    print("[GATEWAY] QUIT message forwarded to remote gateways")

        except Exception as e:
            print(f"[ERROR] Failed to send quit message: {e}")

    def on_message_received(self, nickname, message_type, data, source="local"):
        timestamp = time.strftime("%H:%M:%S")
        
        print(f"[DEBUG] Received {message_type} from {nickname} via {source}, data length: {len(data) if data else 0}")
        
        # Create message object for processing
        try:
            if source == "local":
                msg = ChatMessage(message_type, nickname, data)
            else:
                # For gateway messages, we need to reconstruct with potential TTL
                msg = ChatMessage(message_type, nickname, data)
                
            # Check for duplicate messages (loop prevention)
            if self.message_cache.is_message_seen(msg.msg_id):
                print(f"[LOOP-PREVENT] Dropping duplicate {message_type} from {nickname} (ID: {msg.msg_id[:8]}...)")
                return
                
            # Add message to cache
            self.message_cache.add_message(msg.msg_id)
            self.update_cache_counter()  # Update UI counter
            
            # Forward to remote gateways if this is a local message and we're in gateway mode
            if source == "local" and self.is_gateway_mode:
                # Only forward if the message is not from ourselves to prevent loops
                if nickname != self.nickname:
                    if self.enhanced_gateway_client:
                        results = self.enhanced_gateway_client.send_message_to_gateways(msg, use_retry=True, priority=0)
                        print(f"[GATEWAY-V3] Forwarded {message_type} from {nickname} to remote gateways: {results}")
                    elif self.gateway_client:
                        self.gateway_client.send_message_to_gateways(msg)
                        print(f"[GATEWAY] Forwarded {message_type} from {nickname} to remote gateways")
                    
        except Exception as e:
            print(f"[ERROR] Error processing message: {e}")
            # Continue processing even if forwarding fails

        # Handle different message types
        if message_type == "join":
            # Add peer to list
            self.peer_manager.add_peer(nickname, data)  # data is public key
            self.update_user_list()
            
            gateway_info = f" via {source}" if source != "local" else ""
            self.chat_display.append(f"➕ {nickname} joined the network{gateway_info}")
            
        elif message_type == "chat":
            # Display chat message
            gateway_info = f" [{source}]" if source != "local" else ""
            display_data = data[:500] + "..." if len(data) > 500 else data  # Truncate very long messages for display
            self.chat_display.append(f"[{timestamp}]{gateway_info} {nickname}: {display_data}")
            
        elif message_type == "quit":
            # Remove peer from list
            self.peer_manager.remove_peer(nickname)
            self.update_user_list()
            
            gateway_info = f" via {source}" if source != "local" else ""
            self.chat_display.append(f"➖ {nickname} left the network{gateway_info}")

    def update_user_list(self):
        # Clear and rebuild user list
        while self.user_list.count() > 8:  # Keep status items, remove user entries
            self.user_list.takeItem(8)
        
        # Add connected users
        for nickname, peer_info in self.peer_manager.peers.items():
            self.user_list.addItem(f"👤 {nickname}")

    def start_gateway_services(self):
        try:
            # Start gateway server
            self.gateway_server = GatewayServer()
            self.gateway_server.message_received.connect(self.on_gateway_message_received)
            self.gateway_server.start()
            
            # Start appropriate gateway client based on settings
            if self.use_enhanced_client:
                # Use Phase 3 enhanced client
                self.enhanced_gateway_client = EnhancedGatewayClient()
                self.enhanced_gateway_client.connection_changed.connect(self.on_enhanced_gateway_connection_changed)
                self.enhanced_gateway_client.message_delivered.connect(self.on_message_delivery_status)
                self.enhanced_gateway_client.gateway_error.connect(self.on_gateway_error)
                self.enhanced_gateway_client.start()
                
                print("[GATEWAY] Enhanced gateway client (Phase 3) started")
                self.chat_display.append("⚡ Enhanced gateway client started (Phase 3)")
            else:
                # Use Phase 2 client as fallback
                self.gateway_client = GatewayClient()
                self.gateway_client.connection_changed.connect(self.on_gateway_connection_changed)
                self.gateway_client.message_received.connect(self.on_gateway_message_received)
                self.gateway_client.start()
                
                print("[GATEWAY] Standard gateway client (Phase 2) started")
                self.chat_display.append("🔗 Standard gateway client started (Phase 2)")
            
            # Update UI
            self.user_list.item(2).setText("🔗 Gateway Status: Enabled")
            
            print("[GATEWAY] Gateway services started")
            self.chat_display.append("🚀 Gateway mode activated")
            
        except Exception as e:
            print(f"[GATEWAY] Failed to start gateway services: {e}")
            self.chat_display.append(f"❌ Gateway startup failed: {e}")

    def stop_gateway_services(self):
        try:
            # Stop gateway server
            if self.gateway_server:
                self.gateway_server.stop()
                self.gateway_server = None
            
            # Stop gateway client
            if self.enhanced_gateway_client:
                self.enhanced_gateway_client.stop()
                self.enhanced_gateway_client = None
            
            if self.gateway_client:
                self.gateway_client.stop()
                self.gateway_client = None
            
            # Update UI
            self.user_list.item(2).setText("🔗 Gateway Status: Disabled")
            
            print("[GATEWAY] Gateway services stopped")
            
        except Exception as e:
            print(f"[GATEWAY] Error stopping gateway services: {e}")

    def on_gateway_message_received(self, nickname, message_type, data, source_gateway):
        """Handle messages received from remote gateways"""
        print(f"[GATEWAY] Received {message_type} from {nickname} via gateway {source_gateway}")
        
        # Create message object for processing
        try:
            msg = ChatMessage(message_type, nickname, data)
            
            # Check for duplicate messages (loop prevention)
            if self.message_cache.is_message_seen(msg.msg_id):
                print(f"[GATEWAY] Dropping duplicate {message_type} from {nickname} (ID: {msg.msg_id[:8]}...)")
                return
                
            # Add message to cache
            self.message_cache.add_message(msg.msg_id)
            self.update_cache_counter()
            
            # Process the message directly (don't call on_message_received to avoid double processing)
            timestamp = time.strftime("%H:%M:%S")
            
            if message_type == "join":
                # Add peer to list
                self.peer_manager.add_peer(nickname, data)  # data is public key
                self.update_user_list()
                
                self.chat_display.append(f"➕ {nickname} joined via gateway {source_gateway}")
                
            elif message_type == "chat":
                # Display chat message
                display_data = data[:500] + "..." if len(data) > 500 else data
                self.chat_display.append(f"[{timestamp}] [{source_gateway}] {nickname}: {display_data}")
                
            elif message_type == "quit":
                # Remove peer from list
                self.peer_manager.remove_peer(nickname)
                self.update_user_list()
                
                self.chat_display.append(f"➖ {nickname} left via gateway {source_gateway}")
            
            # Rebroadcast locally using the existing broadcast mechanism
            if message_type == "join":
                # For JOIN messages, use raw broadcast (may be fragmented)
                send_raw_message(msg)
                print(f"[GATEWAY] Relayed JOIN from {nickname} locally")
            else:
                # For other messages, broadcast to local peers
                if self.peer_manager.peers:
                    recipient_pubkeys = {peer_nickname: peer["public_key"] 
                                       for peer_nickname, peer in self.peer_manager.peers.items()
                                       if peer_nickname != nickname}  # Don't send back to originator
                    if recipient_pubkeys:
                        send_encrypted_broadcast(msg, recipient_pubkeys)
                        print(f"[GATEWAY] Relayed {message_type} from {nickname} to {len(recipient_pubkeys)} local peers")
                
        except Exception as e:
            print(f"[GATEWAY] Error processing gateway message: {e}")
            
    def on_gateway_connection_changed(self, gateway_ip, connected):
        """Handle gateway connection status changes"""
        status = "Connected" if connected else "Disconnected"
        print(f"[GATEWAY] {status} to/from {gateway_ip}")
        self.chat_display.append(f"🔗 Gateway {gateway_ip}: {status}")
        
    def on_enhanced_gateway_connection_changed(self, gateway_ip, status):
        """Handle enhanced gateway connection status changes"""
        print(f"[GATEWAY-V3] {gateway_ip}: {status}")
        self.chat_display.append(f"⚡ Gateway {gateway_ip}: {status}")
        
    def on_message_delivery_status(self, message_id, success, details):
        """Handle message delivery status from enhanced client"""
        status_icon = "✅" if success else "❌"
        print(f"[GATEWAY-V3] Message {message_id[:8]}...: {status_icon} {details}")
        
    def on_gateway_error(self, category, severity, message):
        """Handle gateway errors from enhanced client"""
        print(f"[GATEWAY-V3] Error [{category}:{severity}]: {message}")
        self.chat_display.append(f"⚠️ Gateway Error: {message}")

    def update_cache_counter(self):
        """Update cache counter in UI"""
        try:
            cache_stats = self.message_cache.get_cache_stats()
            self.user_list.item(3).setText(f"🛡️ Cache: {cache_stats['total_messages']} messages")
        except Exception as e:
            print(f"[ERROR] Failed to update cache counter: {e}")

    def update_reliability_status(self):
        """Update reliability status indicators"""
        try:
            if self.use_enhanced_client and self.enhanced_gateway_client:
                conn_stats = self.connection_manager.get_stats()
                error_stats = self.error_handler.get_stats()
                retry_stats = self.retry_system.get_stats()
                
                # Update reliability status
                connected_gateways = len([s for s in conn_stats["connections"].values() if s["connected"]])
                self.user_list.item(4).setText(f"⚡ Reliability: {connected_gateways} gateways")
                
                # Update error count
                total_errors = error_stats["total_errors"]
                self.user_list.item(5).setText(f"❌ Errors: {total_errors}")
                
                # Update retry queue
                queue_size = retry_stats["current_queue_size"]
                self.user_list.item(6).setText(f"🔄 Retry Queue: {queue_size}")
            else:
                self.user_list.item(4).setText("⚡ Reliability: Standard mode")
                self.user_list.item(5).setText("❌ Errors: N/A")
                self.user_list.item(6).setText("🔄 Retry Queue: N/A")
                
            # Update fragmentation status
            fragment_stats = self.fragmenter.get_stats()
            partial_count = fragment_stats["partial_messages"]
            self.user_list.item(7).setText(f"📦 Fragments: {partial_count} partial")
            
        except Exception as e:
            print(f"[ERROR] Failed to update reliability status: {e}")

    def toggle_mode(self):
        current_mode = "Gateway" if self.is_gateway_mode else "Client"
        new_mode = "Client" if self.is_gateway_mode else "Gateway"
        
        reply = QMessageBox.question(
            self, 
            "Toggle Mode",
            f"Switch from {current_mode} mode to {new_mode} mode?\n\n"
            f"This will disconnect you from the network.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Disconnect if connected
            if self.is_connected:
                self.disconnect_from_network()
            
            # Toggle mode
            self.is_gateway_mode = not self.is_gateway_mode
            mode_name = "Gateway" if self.is_gateway_mode else "Client"
            self.chat_display.append(f"🔄 Switched to {mode_name} mode")

    def show_about(self):
        QMessageBox.about(
            self, 
            "About Developer", 
            "Anonymous P2P Chat Network\n\n"
            "Developed by: Barış Can Sertkaya\n"
            "Course: CSE471 Data Communications and Computer Networks\n"
            "University: Yeditepe University\n\n"
            "Features:\n"
            "• RSA 2048-bit encryption\n"
            "• IP/MAC spoofing for anonymity\n"
            "• Gateway mode for inter-subnet communication\n"
            "• Loop prevention with TTL\n"
            "• Message fragmentation for large messages\n"
            "• Phase 3 reliability and error handling\n\n"
            "Built with PyQt6, Scapy, and Python cryptography"
        )

    def show_debug_info(self):
        """Show comprehensive debug information"""
        debug_info = []
        
        # Basic info
        debug_info.append("=== NETWORK STATUS ===")
        debug_info.append(f"Connected: {self.is_connected}")
        debug_info.append(f"Nickname: {self.nickname}")
        debug_info.append(f"Mode: {'Gateway' if self.is_gateway_mode else 'Client'}")
        debug_info.append(f"Local IP: {self.local_gateway_ip}")
        
        # Peer info
        debug_info.append(f"\n=== PEERS ({len(self.peer_manager.peers)}) ===")
        for nickname, peer in self.peer_manager.peers.items():
            debug_info.append(f"{nickname}: {peer['public_key'][:50]}...")
        
        # Cache info
        if self.message_cache:
            cache_stats = self.message_cache.get_cache_stats()
            debug_info.append(f"\n=== MESSAGE CACHE ===")
            debug_info.append(f"Total messages: {cache_stats['total_messages']}")
            debug_info.append(f"Total paths: {cache_stats['total_paths']}")
            debug_info.append(f"Running: {cache_stats['running']}")
        
        # Fragmentation info
        fragment_stats = self.fragmenter.get_stats()
        debug_info.append(f"\n=== FRAGMENTATION ===")
        debug_info.append(f"Max fragment size: {fragment_stats['max_fragment_size']}")
        debug_info.append(f"Partial messages: {fragment_stats['partial_messages']}")
        debug_info.append(f"Running: {fragment_stats['running']}")
        
        if fragment_stats['partial_details']:
            debug_info.append("Partial message details:")
            for msg_id, details in fragment_stats['partial_details'].items():
                debug_info.append(f"  {msg_id}: {details['fragments_received']}/{details['total_expected']} "
                                f"from {details['nickname']} ({details['type']}) "
                                f"age: {details['age_seconds']:.1f}s")
        
        # Reliability info (Phase 3)
        if self.use_enhanced_client:
            try:
                conn_stats = self.connection_manager.get_stats()
                error_stats = self.error_handler.get_stats()
                retry_stats = self.retry_system.get_stats()
                
                debug_info.append(f"\n=== RELIABILITY (PHASE 3) ===")
                debug_info.append(f"Connection manager running: {conn_stats['running']}")
                debug_info.append(f"Total errors: {error_stats['total_errors']}")
                debug_info.append(f"Retry queue size: {retry_stats['current_queue_size']}")
                debug_info.append(f"Successful retries: {retry_stats['successful_retries']}")
                
            except Exception as e:
                debug_info.append(f"\n=== RELIABILITY ERROR ===")
                debug_info.append(f"Failed to get stats: {e}")
        
        QMessageBox.information(self, "Debug Information", "\n".join(debug_info))

    def closeEvent(self, event):
        if self.is_connected:
            self.disconnect_from_network()
        
        # Stop cleanup threads
        if hasattr(self, 'fragmenter'):
            self.fragmenter.stop_cleanup_thread()
        
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    window = ChatWindow()
    window.show()
    
    # Start periodic UI updates
    from PyQt6.QtCore import QTimer
    
    def update_ui():
        if window.is_connected:
            window.update_reliability_status()
    
    timer = QTimer()
    timer.timeout.connect(update_ui)
    timer.start(5000)  # Update every 5 seconds
    
    sys.exit(app.exec())
